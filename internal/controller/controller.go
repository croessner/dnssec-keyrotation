// Package controller implements restart-safe DNSSEC rotation state machines.
package controller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/croessner/dnssec-keyrotation/internal/autodns"
	"github.com/croessner/dnssec-keyrotation/internal/config"
	"github.com/croessner/dnssec-keyrotation/internal/dnsprobe"
	"github.com/croessner/dnssec-keyrotation/internal/model"
	"github.com/croessner/dnssec-keyrotation/internal/pdns"
	"github.com/croessner/dnssec-keyrotation/internal/state"
	"github.com/miekg/dns"
)

// Clock provides deterministic transition timestamps.
type Clock interface{ Now() time.Time }
type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// Controller reconciles local keys, registrar state, and observed DNS evidence.
type Controller struct {
	cfg       config.Config
	pdns      pdns.API
	registrar autodns.API
	observer  dnsprobe.Observer
	store     *state.Store
	log       *slog.Logger
	clock     Clock
	mu        sync.Mutex
	notifier  Notifier
}

// Notifier delivers durable controller completion events.
type Notifier interface {
	Send(context.Context, model.Notification) error
}

type discardNotifier struct{}

func (discardNotifier) Send(context.Context, model.Notification) error { return nil }

// ZoneStatus describes the managed state and workflows for one zone.
type ZoneStatus struct {
	Zone             string           `json:"zone"`
	DNSSEC           bool             `json:"dnssec"`
	Scheme           string           `json:"scheme"`
	Managed          bool             `json:"managed"`
	EnrollmentStatus string           `json:"enrollmentStatus"`
	BlockedReason    string           `json:"blockedReason,omitempty"`
	Workflows        []model.Workflow `json:"workflows"`
}

// Status summarizes controller readiness and workflow counts.
type Status struct {
	Mode                 string `json:"mode"`
	Ready                bool   `json:"ready"`
	Zones                int    `json:"zones"`
	Blocked              int    `json:"blocked"`
	EnrollmentArmed      bool   `json:"enrollmentArmed"`
	Enrolling            int    `json:"enrolling"`
	Managed              int    `json:"managed"`
	PendingNotifications int    `json:"pendingNotifications"`
}

// Plan describes the mutations a confirmed rotation would perform.
type Plan struct {
	Kind      model.Kind `json:"kind"`
	Zones     []string   `json:"zones"`
	Mutations []string   `json:"mutations"`
}

// AuditResult compares local public key material with registrar state.
type AuditResult struct {
	Zone           string `json:"zone"`
	Scheme         string `json:"scheme"`
	RegistrarMatch bool   `json:"registrarMatch"`
	Error          string `json:"error,omitempty"`
}

const (
	parentModeExisting = "existing"
	parentModeInitial  = "initial"
)

// New creates a DNSSEC rotation controller.
func New(cfg config.Config, p pdns.API, r autodns.API, o dnsprobe.Observer, s *state.Store, log *slog.Logger) *Controller {
	return &Controller{cfg: cfg, pdns: p, registrar: r, observer: o, store: s, log: log, clock: realClock{}, notifier: discardNotifier{}}
}

// SetNotifier replaces the default no-op completion-event notifier.
func (c *Controller) SetNotifier(notifier Notifier) {
	if notifier != nil {
		c.notifier = notifier
	}
}

// Run reconciles immediately and then at the configured interval.
func (c *Controller) Run(ctx context.Context) error {
	if err := c.Tick(ctx); err != nil {
		c.log.Error("initial reconciliation failed", "error", err)
	}
	t := time.NewTicker(c.cfg.Controller.ReconcileInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := c.Tick(ctx); err != nil {
				c.log.Error("reconciliation failed", "error", err)
			}
		}
	}
}

// Tick performs one serialized reconciliation across all DNSSEC zones.
func (c *Controller) Tick(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var errs []error
	if c.cfg.Mode == "enforce" {
		if err := c.deliverNotifications(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	zones, err := c.pdns.ListZones(ctx)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	seenDNSSEC := make(map[string]bool, len(zones))
	stateSnapshot := c.store.Snapshot()
	for _, z := range zones {
		if _, ok := dns.IsDomainName(dns.Fqdn(z.Name)); !ok || strings.ContainsAny(z.Name, "\r\n") {
			errs = append(errs, fmt.Errorf("invalid PowerDNS zone name %q", z.Name))
			continue
		}
		if z.DNSSEC {
			seenDNSSEC[z.Name] = true
		}
		activeEnrollment := stateSnapshot.Workflows[model.WorkflowKey(z.Name, model.KindEnroll)]
		mustReconcileEnrollment := activeEnrollment.Active()
		if !z.DNSSEC || (!c.selected(z.Name) && !mustReconcileEnrollment) {
			continue
		}
		if err := c.reconcileZone(ctx, z); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", z.Name, err))
			c.log.Error("zone reconciliation blocked", "zone", z.Name, "error", err)
		}
	}
	if c.cfg.Mode == "enforce" {
		for _, workflow := range c.store.Snapshot().Workflows {
			if workflow.Kind == model.KindEnroll && workflow.Active() && !seenDNSSEC[workflow.Zone] {
				errs = append(errs, c.block(workflow.Zone, workflow.Kind, "enrollment zone disappeared or DNSSEC was disabled"))
			}
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) reconcileZone(ctx context.Context, zone model.Zone) error {
	keys, err := c.pdns.ListKeys(ctx, zone.ID)
	if err != nil {
		return err
	}
	scheme := keyScheme(keys)
	if c.cfg.Mode == "observe" {
		return nil
	}
	if err := c.bootstrap(zone, scheme, keys); err != nil {
		return err
	}
	st := c.store.Snapshot()
	var active []model.Workflow
	for _, w := range st.Workflows {
		if w.Zone == zone.Name && w.Active() {
			active = append(active, w)
		}
	}
	if len(active) > 1 {
		return c.block(zone.Name, active[0].Kind, "more than one active workflow for zone")
	}
	if len(active) == 1 {
		if active[0].Kind == model.KindEnroll && active[0].RegistrarAttemptedAt.IsZero() && (!c.cfg.Enrollment.Enabled || !c.selectedEnrollment(zone.Name)) {
			return c.block(zone.Name, model.KindEnroll, "automatic enrollment was disabled or moved out of scope before registrar write")
		}
		return c.advance(ctx, zone, keys, active[0])
	}
	if scheme == "csk" {
		return nil
	}
	if scheme != "split" {
		return c.block(zone.Name, model.KindZSK, "expected exactly one active KSK and one active ZSK")
	}
	now := c.clock.Now()
	z := st.Workflows[model.WorkflowKey(zone.Name, model.KindZSK)]
	k := st.Workflows[model.WorkflowKey(zone.Name, model.KindKSK)]
	if now.Sub(z.LastCompletedAt) >= c.cfg.Rotation.ZSKInterval {
		return c.start(zone.Name, model.KindZSK, false, "")
	}
	if now.Sub(k.LastCompletedAt) >= c.cfg.Rotation.KSKInterval {
		return c.start(zone.Name, model.KindKSK, false, "")
	}
	return nil
}

func (c *Controller) bootstrap(zone model.Zone, scheme string, keys []model.Key) error {
	now := c.clock.Now()
	return c.store.Update(func(s *model.State) error {
		switch scheme {
		case "split":
			for _, kind := range []model.Kind{model.KindZSK, model.KindKSK} {
				k := model.WorkflowKey(zone.Name, kind)
				if _, ok := s.Workflows[k]; !ok {
					s.Workflows[k] = model.Workflow{Zone: zone.Name, Kind: kind, Phase: model.PhaseIdle, LastCompletedAt: now}
				}
			}
		case "csk":
			k := model.WorkflowKey(zone.Name, model.KindSplit)
			if _, ok := s.Workflows[k]; !ok {
				s.Workflows[k] = model.Workflow{Zone: zone.Name, Kind: model.KindSplit, Phase: model.PhaseIdle, LastCompletedAt: now}
			}
		}
		enrollKey := model.WorkflowKey(zone.Name, model.KindEnroll)
		if _, known := s.Workflows[enrollKey]; known || s.EnrollmentArmedAt.IsZero() || !c.cfg.Enrollment.Enabled || !c.selectedEnrollment(zone.Name) {
			return nil
		}
		if scheme == "csk" {
			s.Workflows[enrollKey] = model.Workflow{Zone: zone.Name, ZoneID: zone.ID, Kind: model.KindEnroll, Phase: model.PhaseIdle, LastCompletedAt: now, EnrollmentDisposition: "ineligible", LastError: "automatic enrollment requires a clean split KSK/ZSK zone at first discovery"}
			return nil
		}
		ksk, zsk, fingerprint, err := validateEnrollmentInventory(zone.Name, keys, 0, 0, "", c.cfg.Enrollment.AllowedAlgorithms)
		pending, recent := 0, 0
		for _, workflow := range s.Workflows {
			if workflow.Kind != model.KindEnroll {
				continue
			}
			if workflow.Active() {
				pending++
			}
			if !workflow.DiscoveredAt.IsZero() && now.Sub(workflow.DiscoveredAt) < 24*time.Hour {
				recent++
			}
		}
		if pending >= c.cfg.Enrollment.MaxPending || recent >= c.cfg.Enrollment.MaxNewPerDay {
			s.Workflows[enrollKey] = model.Workflow{Zone: zone.Name, ZoneID: zone.ID, Kind: model.KindEnroll, Phase: model.PhaseBlocked, DiscoveredAt: now, LastError: "automatic enrollment circuit breaker exceeded"}
			return nil
		}
		candidate := model.Workflow{Zone: zone.Name, ZoneID: zone.ID, Kind: model.KindEnroll, Phase: model.PhaseEnrollDiscovered, PhaseStartedAt: now, NextActionAt: now, DiscoveredAt: now, ParentMode: parentModeInitial, EnrollmentDisposition: "candidate"}
		if err == nil {
			candidate.NewKeyID = ksk.ID
			candidate.NewZSKID = zsk.ID
			candidate.KeysetFingerprint = fingerprint
			candidate.NextActionAt = now.Add(c.cfg.Enrollment.DiscoveryGrace)
		} else {
			candidate.LastError = "waiting for a stable clean split inventory: " + err.Error()
		}
		s.Workflows[enrollKey] = candidate
		return nil
	})
}

func (c *Controller) start(zone string, kind model.Kind, manual bool, idem string) error {
	now := c.clock.Now()
	return c.store.Update(func(s *model.State) error {
		for _, w := range s.Workflows {
			if w.Zone == zone && w.Active() {
				return fmt.Errorf("zone already has active %s workflow", w.Kind)
			}
		}
		k := model.WorkflowKey(zone, kind)
		w, ok := s.Workflows[k]
		if !ok {
			w = model.Workflow{Zone: zone, Kind: kind}
		}
		w.Phase = model.PhasePrepublish
		w.PhaseStartedAt = now
		w.NextActionAt = now
		w.LastError = ""
		w.Attempts = 0
		w.Manual = manual
		w.IdempotencyKey = idem
		s.Workflows[k] = w
		if idem != "" {
			s.Idempotency[idem] = k
		}
		return nil
	})
}

func (c *Controller) advance(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	if !w.NextActionAt.IsZero() && c.clock.Now().Before(w.NextActionAt) {
		return nil
	}
	var err error
	switch w.Phase {
	case model.PhasePrepublish:
		err = c.prepublish(ctx, zone, keys, w)
	case model.PhaseWaitPublish:
		err = c.waitPublish(ctx, zone, keys, w)
	case model.PhaseActivateNew:
		err = c.activateNew(ctx, zone, keys, w)
	case model.PhaseWaitNewSignature:
		err = c.waitNewSignature(ctx, zone, keys, w)
	case model.PhaseDeactivateOld:
		err = c.deactivateOld(ctx, zone, keys, w)
	case model.PhaseParentRemove:
		err = c.parentReplace(ctx, zone, keys, w)
	case model.PhaseWaitParentRemove:
		err = c.waitParentReplace(ctx, zone, keys, w)
	case model.PhaseWaitRetire:
		err = c.waitRetire(ctx, zone, keys, w)
	case model.PhaseDeleteOld:
		err = c.deleteOld(ctx, zone, keys, w)
	case model.PhaseEnrollDiscovered:
		err = c.enrollDiscovered(ctx, zone, keys, w)
	case model.PhaseEnrollWaitPublish:
		err = c.enrollWaitPublish(ctx, zone, keys, w)
	case model.PhaseEnrollParentAdd:
		err = c.enrollParentAdd(ctx, zone, keys, w)
	case model.PhaseEnrollWaitParent:
		err = c.enrollWaitParent(ctx, zone, keys, w)
	case model.PhaseBlocked:
		return nil
	default:
		return fmt.Errorf("unknown phase %q", w.Phase)
	}
	if err != nil {
		_ = c.recordRetry(w, err)
		return err
	}
	return nil
}

func (c *Controller) prepublish(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	typ := string(w.Kind)
	switch w.Kind {
	case model.KindSplit:
		typ = "csk"
	}
	if w.OldKeyID == 0 {
		old, err := exactlyOneActive(keys, typ)
		if err != nil {
			return c.block(zone.Name, w.Kind, err.Error())
		}
		return c.transition(w, model.PhasePrepublish, c.clock.Now(), func(x *model.Workflow) { x.OldKeyID = old.ID })
	}
	old, ok := byID(keys, w.OldKeyID)
	if !ok {
		return c.block(zone.Name, w.Kind, "recorded old key missing")
	}
	algorithm := old.Algorithm
	if algorithm == "" {
		algorithm = c.cfg.Rotation.Algorithm
	}
	if w.Kind == model.KindSplit && w.ParentMode == "" {
		oldData, err := dnsprobe.DNSSECDataForKey(zone.Name, old)
		if err != nil {
			return err
		}
		remote, err := c.registrar.DomainDNSSEC(ctx, zone.Name)
		if err != nil {
			return err
		}
		mode := ""
		switch {
		case remote.Enabled && sameMaterial(remote.Data, []model.DNSSECData{oldData}):
			mode = parentModeExisting
		case !remote.Enabled && len(remote.Data) == 0:
			if err := c.observer.NoDSEvidence(ctx, zone.Name); err != nil {
				return fmt.Errorf("initial delegation requires proven parent DS absence: %w", err)
			}
			mode = parentModeInitial
		default:
			return c.block(zone.Name, w.Kind, "InternetX DNSSEC state is neither exact active old CSK nor exact disabled-empty initial state")
		}
		return c.transition(w, model.PhasePrepublish, c.clock.Now(), func(x *model.Workflow) { x.ParentMode = mode })
	}
	if w.Kind == model.KindSplit {
		if w.NewKeyID == 0 {
			k, err := c.adoptOrCreate(ctx, zone, keys, w, "ksk", algorithm, old.ID, true, true, false)
			if err != nil {
				return err
			}
			return c.transition(w, model.PhasePrepublish, c.clock.Now(), func(x *model.Workflow) { x.NewKeyID = k.ID })
		}
		if w.NewZSKID == 0 {
			k, err := c.adoptOrCreate(ctx, zone, keys, w, "zsk", algorithm, old.ID, false, true, true)
			if err != nil {
				return err
			}
			return c.transition(w, model.PhaseWaitPublish, c.clock.Now(), func(x *model.Workflow) { x.NewZSKID = k.ID; x.EvidenceAt = time.Time{} })
		}
		return c.transition(w, model.PhaseWaitPublish, c.clock.Now(), func(x *model.Workflow) { x.EvidenceAt = time.Time{} })
	}
	if w.NewKeyID == 0 {
		active := w.Kind == model.KindKSK
		k, err := c.adoptOrCreate(ctx, zone, keys, w, string(w.Kind), algorithm, old.ID, active, false, false)
		if err != nil {
			return err
		}
		return c.transition(w, model.PhaseWaitPublish, c.clock.Now(), func(x *model.Workflow) { x.NewKeyID = k.ID; x.EvidenceAt = time.Time{} })
	}
	return c.transition(w, model.PhaseWaitPublish, c.clock.Now(), func(x *model.Workflow) { x.EvidenceAt = time.Time{} })
}

func (c *Controller) adoptOrCreate(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow, typ, algorithm string, oldID int, active, allowTransitionalCSK, zskSlot bool) (model.Key, error) {
	var candidates []model.Key
	for _, k := range keys {
		if k.ID == oldID || k.Active != active || !k.Published {
			continue
		}
		if (zskSlot && k.ID == w.NewKeyID) || (!zskSlot && k.ID == w.NewZSKID && w.NewZSKID != 0) {
			return model.Key{}, fmt.Errorf("candidate %s key %d reuses the other replacement slot", typ, k.ID)
		}
		if k.KeyType != typ && (!allowTransitionalCSK || k.KeyType != "csk") {
			continue
		}
		if k.Algorithm == "" || !strings.EqualFold(k.Algorithm, algorithm) {
			return model.Key{}, fmt.Errorf("candidate %s key %d has algorithm %q, want %q", typ, k.ID, k.Algorithm, algorithm)
		}
		data, err := validatedKeyRole(zone.Name, k, typ, allowTransitionalCSK)
		if err != nil {
			return model.Key{}, fmt.Errorf("candidate %s key: %w", typ, err)
		}
		if err := validateAlgorithmLabel(k.Algorithm, data.Algorithm); err != nil {
			return model.Key{}, fmt.Errorf("candidate %s key %d: %w", typ, k.ID, err)
		}
		candidates = append(candidates, k)
	}
	if len(candidates) > 1 {
		return model.Key{}, fmt.Errorf("multiple candidate %s keys", typ)
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	attemptedAt := w.NewKeyCreateAttemptedAt
	if zskSlot {
		attemptedAt = w.NewZSKCreateAttemptedAt
	}
	if !attemptedAt.IsZero() {
		return model.Key{}, fmt.Errorf("%s create was already attempted at %s; waiting for one exact read-back candidate", typ, attemptedAt.UTC().Format(time.RFC3339))
	}
	if err := c.recordCreateAttempt(w, zskSlot); err != nil {
		return model.Key{}, err
	}
	created, err := c.pdns.CreateKey(ctx, zone.ID, typ, algorithm, active)
	if err != nil {
		return model.Key{}, err
	}
	if created.ID <= 0 || created.ID == oldID || (zskSlot && created.ID == w.NewKeyID) || (!zskSlot && created.ID == w.NewZSKID && w.NewZSKID != 0) || created.Active != active || !created.Published {
		return model.Key{}, fmt.Errorf("created %s response has invalid id or active/published state", typ)
	}
	if created.Algorithm == "" || !strings.EqualFold(created.Algorithm, algorithm) {
		return model.Key{}, fmt.Errorf("created %s response has algorithm %q, want %q", typ, created.Algorithm, algorithm)
	}
	data, err := validatedKeyRole(zone.Name, created, typ, allowTransitionalCSK)
	if err != nil {
		return model.Key{}, fmt.Errorf("created %s response: %w", typ, err)
	}
	if err := validateAlgorithmLabel(created.Algorithm, data.Algorithm); err != nil {
		return model.Key{}, fmt.Errorf("created %s response: %w", typ, err)
	}
	return created, nil
}

func (c *Controller) recordCreateAttempt(w model.Workflow, zskSlot bool) error {
	now := c.clock.Now()
	return c.store.Update(func(s *model.State) error {
		key := model.WorkflowKey(w.Zone, w.Kind)
		current, ok := s.Workflows[key]
		if !ok || current.Phase != model.PhasePrepublish || current.OldKeyID != w.OldKeyID || current.NewKeyID != w.NewKeyID || current.NewZSKID != w.NewZSKID {
			return fmt.Errorf("workflow changed before key create intent could be persisted")
		}
		attemptedAt := current.NewKeyCreateAttemptedAt
		if zskSlot {
			attemptedAt = current.NewZSKCreateAttemptedAt
		}
		if !attemptedAt.IsZero() {
			return fmt.Errorf("key create was already attempted at %s", attemptedAt.UTC().Format(time.RFC3339))
		}
		if zskSlot {
			current.NewZSKCreateAttemptedAt = now
		} else {
			current.NewKeyCreateAttemptedAt = now
		}
		s.Workflows[key] = current
		return nil
	})
}

func (c *Controller) waitPublish(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	old, newKey, err := recordedKeys(keys, w.OldKeyID, w.NewKeyID)
	if err != nil {
		return c.block(zone.Name, w.Kind, err.Error())
	}
	switch w.Kind {
	case model.KindSplit:
		_, ok := byID(keys, w.NewZSKID)
		if !ok {
			return c.block(zone.Name, w.Kind, "recorded new ZSK missing")
		}
	}
	if err := validatePrepublishInventory(zone.Name, keys, w); err != nil {
		return c.block(zone.Name, w.Kind, err.Error())
	}
	evidenceKeys := publishedKeys(keys)
	var ttl time.Duration
	if w.Kind == model.KindSplit && w.ParentMode == parentModeInitial {
		ttl, err = c.observer.AuthoritativeDNSKEYEvidence(ctx, zone.Name, evidenceKeys...)
	} else {
		ttl, err = c.observer.DNSKEYEvidence(ctx, zone.Name, evidenceKeys...)
	}
	if err != nil {
		return err
	}
	if w.Kind == model.KindKSK || w.Kind == model.KindSplit {
		checkSignature := c.observer.DNSKEYRRSIGBy
		if w.Kind == model.KindSplit && w.ParentMode == parentModeInitial {
			checkSignature = c.observer.AuthoritativeDNSKEYRRSIGBy
		}
		if err := checkSignature(ctx, zone.Name, old); err != nil {
			return fmt.Errorf("old KSK/CSK overlap signature missing: %w", err)
		}
		if err := checkSignature(ctx, zone.Name, newKey); err != nil {
			return fmt.Errorf("new KSK overlap signature missing: %w", err)
		}
	}
	if w.EvidenceAt.IsZero() {
		wait := maxDuration(ttl, c.cfg.Rotation.MinimumDNSKEYWait) + c.cfg.Controller.PropagationMargin
		return c.transition(w, model.PhaseWaitPublish, c.clock.Now().Add(wait), func(x *model.Workflow) { x.DNSKEYTTL = int64(ttl / time.Second); x.EvidenceAt = c.clock.Now() })
	}
	next := model.PhaseActivateNew
	if w.Kind == model.KindKSK || w.Kind == model.KindSplit {
		next = model.PhaseParentRemove
	}
	return c.transition(w, next, c.clock.Now(), func(x *model.Workflow) { x.EvidenceAt = time.Time{} })
}

func (c *Controller) activateNew(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	if w.Kind == model.KindSplit {
		preErr := validatePrepublishInventory(zone.Name, keys, w)
		postErr := validateActiveSplitInventory(zone.Name, keys, w)
		if preErr != nil && postErr != nil {
			return c.block(zone.Name, w.Kind, fmt.Sprintf("split activation inventory is neither exact pre-state nor exact post-state; full DNSKEY prepublication recovery may be required: pre=%v; post=%v", preErr, postErr))
		}
	}
	var k model.Key
	var ok bool
	if w.Kind == model.KindSplit {
		k, ok = byID(keys, w.NewZSKID)
	} else {
		k, ok = byID(keys, w.NewKeyID)
	}
	if !ok {
		return c.block(zone.Name, w.Kind, "new signing key missing")
	}
	if !k.Active {
		if err := c.pdns.SetKey(ctx, zone.ID, k, true, true); err != nil {
			return err
		}
	}
	return c.transition(w, model.PhaseWaitNewSignature, c.clock.Now(), func(x *model.Workflow) { x.EvidenceAt = time.Time{} })
}

func (c *Controller) waitNewSignature(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	old, _, err := recordedKeys(keys, w.OldKeyID, w.NewKeyID)
	if err != nil {
		return err
	}
	newSigner, ok := byID(keys, w.NewKeyID)
	if w.Kind == model.KindSplit {
		newSigner, ok = byID(keys, w.NewZSKID)
	}
	if !ok {
		return c.block(zone.Name, w.Kind, "new signer missing")
	}
	if err := c.observer.RRSIGBy(ctx, zone.Name, newSigner); err != nil {
		return err
	}
	if !newSigner.Active || !newSigner.Published {
		return c.block(zone.Name, w.Kind, "new signing key is not active and published")
	}
	if w.ZoneTTL == 0 {
		detail, err := c.pdns.GetZone(ctx, zone.ID)
		if err != nil {
			return err
		}
		ttl := maxTTL(detail)
		if ttl <= 0 {
			return c.block(zone.Name, w.Kind, "zone maximum TTL is zero")
		}
		return c.transition(w, model.PhaseWaitNewSignature, c.clock.Now(), func(x *model.Workflow) { x.ZoneTTL = int64(ttl / time.Second) })
	}
	if w.Kind == model.KindSplit {
		if err := c.observer.RRSIGBy(ctx, zone.Name, old); err != nil {
			return fmt.Errorf("old CSK overlap signature missing: %w", err)
		}
		if w.EvidenceAt.IsZero() {
			wait := time.Duration(w.ZoneTTL)*time.Second + c.cfg.Controller.PropagationMargin
			return c.transition(w, model.PhaseWaitNewSignature, c.clock.Now().Add(wait), func(x *model.Workflow) { x.EvidenceAt = c.clock.Now() })
		}
	}
	return c.transition(w, model.PhaseDeactivateOld, c.clock.Now(), func(x *model.Workflow) { x.EvidenceAt = time.Time{} })
}

func (c *Controller) deactivateOld(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	if w.Kind == model.KindSplit {
		preErr := validateActiveSplitInventory(zone.Name, keys, w)
		postErr := validateDeactivatedSplitInventory(zone.Name, keys, w)
		if preErr != nil && postErr != nil {
			return c.block(zone.Name, w.Kind, fmt.Sprintf("split deactivation inventory is neither exact pre-state nor exact post-state: pre=%v; post=%v", preErr, postErr))
		}
	}
	old, newKey, err := recordedKeys(keys, w.OldKeyID, w.NewKeyID)
	if err != nil {
		return err
	}
	if !newKey.Active || !newKey.Published {
		return c.block(zone.Name, w.Kind, "replacement key is not active and published")
	}
	if w.Kind == model.KindZSK {
		if err := c.observer.RRSIGBy(ctx, zone.Name, newKey); err != nil {
			return fmt.Errorf("new ZSK signature missing before old-key deactivation: %w", err)
		}
	} else {
		if err := c.observer.DNSKEYRRSIGBy(ctx, zone.Name, newKey); err != nil {
			return fmt.Errorf("new KSK signature missing before old-key deactivation: %w", err)
		}
		if err := c.observer.DSEvidence(ctx, zone.Name, []model.Key{newKey}); err != nil {
			return fmt.Errorf("parent DS evidence missing before old-key deactivation: %w", err)
		}
	}
	switch w.Kind {
	case model.KindSplit:
		z, ok := byID(keys, w.NewZSKID)
		if !ok || !z.Active || !z.Published {
			return c.block(zone.Name, w.Kind, "replacement ZSK is not active and published")
		}
		if err := c.observer.RRSIGBy(ctx, zone.Name, z); err != nil {
			return fmt.Errorf("new ZSK signature missing before CSK deactivation: %w", err)
		}
	}
	if _, err := c.observer.DNSKEYEvidence(ctx, zone.Name, publishedKeys(keys)...); err != nil {
		return fmt.Errorf("replacement DNSKEY evidence missing before old-key deactivation: %w", err)
	}
	if w.Kind != model.KindKSK {
		detail, err := c.pdns.GetZone(ctx, zone.ID)
		if err != nil {
			return err
		}
		current := int64(maxTTL(detail) / time.Second)
		if current <= 0 {
			return c.block(zone.Name, w.Kind, "zone maximum TTL is zero")
		}
		if current > w.ZoneTTL {
			wait := time.Duration(current)*time.Second + c.cfg.Controller.PropagationMargin
			return c.transition(w, model.PhaseDeactivateOld, c.clock.Now().Add(wait), func(x *model.Workflow) {
				x.ZoneTTL = current
				x.EvidenceAt = c.clock.Now()
			})
		}
	}
	if old.Active {
		if err := c.pdns.SetKey(ctx, zone.ID, old, false, true); err != nil {
			return err
		}
	}
	if w.Kind == model.KindKSK {
		return c.transition(w, model.PhaseDeleteOld, c.clock.Now(), nil)
	}
	wait := time.Duration(w.ZoneTTL)*time.Second + c.cfg.Controller.PropagationMargin
	return c.transition(w, model.PhaseWaitRetire, c.clock.Now().Add(wait), nil)
}

func (c *Controller) enrollDiscovered(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	if w.NewKeyID == 0 || w.NewZSKID == 0 || w.KeysetFingerprint == "" {
		if keyScheme(keys) == "csk" {
			return c.store.Update(func(s *model.State) error {
				current := s.Workflows[model.WorkflowKey(w.Zone, w.Kind)]
				current.Phase = model.PhaseIdle
				current.LastCompletedAt = c.clock.Now()
				current.NextActionAt = time.Time{}
				current.EnrollmentDisposition = "ineligible"
				current.LastError = "automatic enrollment requires a clean split KSK/ZSK zone at first discovery"
				s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = current
				return nil
			})
		}
		ksk, zsk, fingerprint, err := validateEnrollmentInventory(zone.Name, keys, 0, 0, "", c.cfg.Enrollment.AllowedAlgorithms)
		if err != nil {
			return fmt.Errorf("waiting for a stable clean split inventory: %w", err)
		}
		return c.transition(w, model.PhaseEnrollDiscovered, c.clock.Now().Add(c.cfg.Enrollment.DiscoveryGrace), func(x *model.Workflow) {
			x.NewKeyID = ksk.ID
			x.NewZSKID = zsk.ID
			x.KeysetFingerprint = fingerprint
			x.EvidenceAt = time.Time{}
			x.DNSKEYTTL = 0
		})
	}
	ksk, zsk, _, err := validateEnrollmentInventory(zone.Name, keys, w.NewKeyID, w.NewZSKID, w.KeysetFingerprint, c.cfg.Enrollment.AllowedAlgorithms)
	if err != nil {
		return c.block(zone.Name, w.Kind, "enrollment inventory drifted during discovery: "+err.Error())
	}
	if zone.ID != w.ZoneID {
		return c.block(zone.Name, w.Kind, "PowerDNS zone identity changed during enrollment discovery")
	}
	remote, err := c.registrar.DomainDNSSEC(ctx, zone.Name)
	if err != nil {
		return err
	}
	expected, err := dnsprobe.DNSSECDataForKey(zone.Name, ksk)
	if err != nil {
		return err
	}
	if remote.Enabled {
		if !sameMaterial(remote.Data, []model.DNSSECData{expected}) {
			return c.block(zone.Name, w.Kind, "InternetX already contains non-matching DNSSEC material")
		}
		if err := c.validateEnrollmentEvidence(ctx, zone.Name, keys, ksk, zsk, true); err != nil {
			return fmt.Errorf("existing enrollment adoption evidence: %w", err)
		}
		if _, err := c.observer.AuthoritativeDSEvidence(ctx, zone.Name, []model.Key{ksk}); err != nil {
			return fmt.Errorf("existing enrollment authoritative DS evidence: %w", err)
		}
		if err := c.observer.DSEvidence(ctx, zone.Name, []model.Key{ksk}); err != nil {
			return fmt.Errorf("existing enrollment validating DS evidence: %w", err)
		}
		return c.complete(w)
	}
	if len(remote.Data) != 0 {
		return c.block(zone.Name, w.Kind, "InternetX initial enrollment state is not disabled-empty")
	}
	if err := c.observer.NoDSEvidence(ctx, zone.Name); err != nil {
		return fmt.Errorf("initial enrollment requires proven parent DS absence: %w", err)
	}
	if err := c.observer.DelegationEvidence(ctx, zone.Name, c.cfg.DNS.ExpectedNameservers); err != nil {
		return fmt.Errorf("initial enrollment requires exact parent delegation: %w", err)
	}
	return c.transition(w, model.PhaseEnrollWaitPublish, c.clock.Now(), func(x *model.Workflow) { x.EvidenceAt = time.Time{}; x.DNSKEYTTL = 0 })
}

func (c *Controller) enrollWaitPublish(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	ksk, zsk, _, err := validateEnrollmentInventory(zone.Name, keys, w.NewKeyID, w.NewZSKID, w.KeysetFingerprint, c.cfg.Enrollment.AllowedAlgorithms)
	if err != nil || zone.ID != w.ZoneID {
		if err == nil {
			err = errors.New("PowerDNS zone identity changed")
		}
		return c.block(zone.Name, w.Kind, "enrollment inventory drifted during publication wait: "+err.Error())
	}
	ttl, err := c.observer.AuthoritativeDNSKEYEvidence(ctx, zone.Name, publishedKeys(keys)...)
	if err != nil {
		return err
	}
	if err := c.observer.AuthoritativeDNSKEYRRSIGBy(ctx, zone.Name, ksk); err != nil {
		return fmt.Errorf("enrollment KSK DNSKEY signature: %w", err)
	}
	if err := c.observer.AuthoritativeRRSIGBy(ctx, zone.Name, zsk); err != nil {
		return fmt.Errorf("enrollment ZSK zone signature: %w", err)
	}
	if err := c.observer.DelegationEvidence(ctx, zone.Name, c.cfg.DNS.ExpectedNameservers); err != nil {
		return err
	}
	if w.EvidenceAt.IsZero() {
		wait := maxDuration(ttl, c.cfg.Rotation.MinimumDNSKEYWait) + c.cfg.Controller.PropagationMargin
		return c.transition(w, model.PhaseEnrollWaitPublish, c.clock.Now().Add(wait), func(x *model.Workflow) { x.EvidenceAt = c.clock.Now(); x.DNSKEYTTL = int64(ttl / time.Second) })
	}
	return c.transition(w, model.PhaseEnrollParentAdd, c.clock.Now(), func(x *model.Workflow) { x.EvidenceAt = time.Time{} })
}

func (c *Controller) enrollParentAdd(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	if w.Phase != model.PhaseEnrollParentAdd {
		return nil
	}
	if w.RegistrarAttemptedAt.IsZero() && c.store.Snapshot().EnrollmentArmedAt.IsZero() {
		return c.block(zone.Name, w.Kind, "automatic enrollment is disarmed before registrar write")
	}
	ksk, zsk, _, err := validateEnrollmentInventory(zone.Name, keys, w.NewKeyID, w.NewZSKID, w.KeysetFingerprint, c.cfg.Enrollment.AllowedAlgorithms)
	if err != nil || zone.ID != w.ZoneID {
		if err == nil {
			err = errors.New("PowerDNS zone identity changed")
		}
		return c.block(zone.Name, w.Kind, "enrollment inventory drifted before parent write: "+err.Error())
	}
	if err := c.validateEnrollmentEvidence(ctx, zone.Name, keys, ksk, zsk, false); err != nil {
		return fmt.Errorf("enrollment pre-write evidence: %w", err)
	}
	if err := c.observer.NoDSEvidence(ctx, zone.Name); err != nil {
		return c.block(zone.Name, w.Kind, "parent DS appeared before enrollment write: "+err.Error())
	}
	newData, err := dnsprobe.DNSSECDataForKey(zone.Name, ksk)
	if err != nil {
		return err
	}
	payloadHash := dnssecPayloadHash(newData)
	if w.RegistrarPayloadHash != "" && w.RegistrarPayloadHash != payloadHash {
		return c.block(zone.Name, w.Kind, "recorded InternetX enrollment payload hash changed")
	}
	remote, err := c.registrar.DomainDNSSEC(ctx, zone.Name)
	if err != nil {
		return err
	}
	if remote.Enabled && sameMaterial(remote.Data, []model.DNSSECData{newData}) {
		return c.transition(w, model.PhaseEnrollWaitParent, c.clock.Now(), func(x *model.Workflow) { x.EvidenceAt = time.Time{} })
	}
	if remote.Enabled || len(remote.Data) != 0 {
		return c.block(zone.Name, w.Kind, "InternetX initial enrollment state changed before write")
	}
	if w.RegistrarCTID == "" {
		armed := c.store.Snapshot().EnrollmentArmedAt.UTC().Format(time.RFC3339Nano)
		sum := sha256.Sum256([]byte(armed + "|" + zone.Name + "|" + w.KeysetFingerprint + "|enroll"))
		return c.transition(w, model.PhaseEnrollParentAdd, c.clock.Now(), func(x *model.Workflow) {
			x.RegistrarCTID = fmt.Sprintf("dnssec-%x", sum[:16])
			x.RegistrarPayloadHash = payloadHash
		})
	}
	if w.RegistrarPayloadHash == "" {
		return c.block(zone.Name, w.Kind, "InternetX enrollment payload hash was not persisted before write")
	}
	if !w.RegistrarAttemptedAt.IsZero() {
		if c.clock.Now().Sub(w.RegistrarAttemptedAt) >= 24*time.Hour {
			return c.block(zone.Name, w.Kind, "ambiguous InternetX enrollment write did not converge within 24h; manual reconciliation required")
		}
		return fmt.Errorf("InternetX enrollment write outcome is ambiguous; waiting for read-back without resubmitting")
	}
	attemptedAt := c.clock.Now()
	if err := c.store.Update(func(s *model.State) error {
		current := s.Workflows[model.WorkflowKey(w.Zone, w.Kind)]
		if current.Phase != model.PhaseEnrollParentAdd || current.RegistrarCTID != w.RegistrarCTID || !current.RegistrarAttemptedAt.IsZero() {
			return errors.New("enrollment workflow changed before registrar intent could be persisted")
		}
		current.RegistrarAttemptedAt = attemptedAt
		s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = current
		return nil
	}); err != nil {
		return err
	}
	job, err := c.registrar.UpdateDNSSEC(ctx, zone.Name, []model.DNSSECData{newData}, w.RegistrarCTID)
	if err != nil {
		return err
	}
	if job.ID <= 0 {
		return c.block(zone.Name, w.Kind, "InternetX enrollment acknowledgement omitted a positive job id")
	}
	return c.transition(w, model.PhaseEnrollWaitParent, c.clock.Now(), func(x *model.Workflow) {
		x.RegistrarSTID = job.STID
		x.RegistrarJobID = job.ID
		x.RegistrarJobStatus = job.Status
		x.EvidenceAt = time.Time{}
	})
}

func (c *Controller) enrollWaitParent(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	ksk, zsk, _, err := validateEnrollmentInventory(zone.Name, keys, w.NewKeyID, w.NewZSKID, w.KeysetFingerprint, c.cfg.Enrollment.AllowedAlgorithms)
	if err != nil || zone.ID != w.ZoneID {
		if err == nil {
			err = errors.New("PowerDNS zone identity changed")
		}
		return c.block(zone.Name, w.Kind, "enrollment inventory drifted during parent wait: "+err.Error())
	}
	if w.RegistrarJobID > 0 && !jobSucceeded(w.RegistrarJobStatus) {
		status, err := c.registrar.JobStatus(ctx, w.RegistrarJobID)
		if err != nil {
			return err
		}
		if jobFailed(status) {
			return c.block(zone.Name, w.Kind, fmt.Sprintf("InternetX enrollment job %d finished with %s", w.RegistrarJobID, status))
		}
		if !jobSucceeded(status) {
			return fmt.Errorf("InternetX enrollment job %d is %s", w.RegistrarJobID, status)
		}
		return c.transition(w, model.PhaseEnrollWaitParent, c.clock.Now(), func(x *model.Workflow) { x.RegistrarJobStatus = status })
	}
	ttl, err := c.observer.AuthoritativeDSEvidence(ctx, zone.Name, []model.Key{ksk})
	if err != nil {
		return err
	}
	if w.EvidenceAt.IsZero() {
		wait := maxDuration(ttl, c.cfg.Rotation.MinimumParentWait) + c.cfg.Controller.PropagationMargin
		return c.transition(w, model.PhaseEnrollWaitParent, c.clock.Now().Add(wait), func(x *model.Workflow) { x.ParentDSTTL = int64(ttl / time.Second); x.EvidenceAt = c.clock.Now() })
	}
	if observed := int64(ttl / time.Second); observed > w.ParentDSTTL {
		wait := maxDuration(ttl, c.cfg.Rotation.MinimumParentWait) + c.cfg.Controller.PropagationMargin
		return c.transition(w, model.PhaseEnrollWaitParent, c.clock.Now().Add(wait), func(x *model.Workflow) { x.ParentDSTTL = observed; x.EvidenceAt = c.clock.Now() })
	}
	if err := c.validateEnrollmentEvidence(ctx, zone.Name, keys, ksk, zsk, true); err != nil {
		return err
	}
	if err := c.observer.DSEvidence(ctx, zone.Name, []model.Key{ksk}); err != nil {
		return err
	}
	remote, err := c.registrar.DomainDNSSEC(ctx, zone.Name)
	if err != nil {
		return err
	}
	data, err := dnsprobe.DNSSECDataForKey(zone.Name, ksk)
	if err != nil {
		return err
	}
	if !remote.Enabled || !sameMaterial(remote.Data, []model.DNSSECData{data}) {
		return c.block(zone.Name, w.Kind, "InternetX enrollment material is not the exact recorded KSK after parent wait")
	}
	return c.complete(w)
}

func (c *Controller) validateEnrollmentEvidence(ctx context.Context, zone string, keys []model.Key, ksk, zsk model.Key, recursive bool) error {
	if err := c.observer.DelegationEvidence(ctx, zone, c.cfg.DNS.ExpectedNameservers); err != nil {
		return fmt.Errorf("parent delegation: %w", err)
	}
	if recursive {
		if _, err := c.observer.DNSKEYEvidence(ctx, zone, publishedKeys(keys)...); err != nil {
			return err
		}
		if err := c.observer.DNSKEYRRSIGBy(ctx, zone, ksk); err != nil {
			return err
		}
		return c.observer.RRSIGBy(ctx, zone, zsk)
	}
	if _, err := c.observer.AuthoritativeDNSKEYEvidence(ctx, zone, publishedKeys(keys)...); err != nil {
		return err
	}
	if err := c.observer.AuthoritativeDNSKEYRRSIGBy(ctx, zone, ksk); err != nil {
		return err
	}
	return c.observer.AuthoritativeRRSIGBy(ctx, zone, zsk)
}

func (c *Controller) parentReplace(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	if w.RegistrarCTID == "" {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|parent-replace", w.Zone, w.Kind, w.PhaseStartedAt.UTC().Format(time.RFC3339Nano))))
		ctid := fmt.Sprintf("dnssec-%x", sum[:16])
		return c.transition(w, model.PhaseParentRemove, c.clock.Now(), func(x *model.Workflow) { x.RegistrarCTID = ctid })
	}
	old, newKey, err := recordedKeys(keys, w.OldKeyID, w.NewKeyID)
	if err != nil {
		return err
	}
	if err := validatePrepublishInventory(zone.Name, keys, w); err != nil {
		return c.block(zone.Name, w.Kind, err.Error())
	}
	checkSignature := c.observer.DNSKEYRRSIGBy
	if w.Kind == model.KindSplit && w.ParentMode == parentModeInitial {
		checkSignature = c.observer.AuthoritativeDNSKEYRRSIGBy
	}
	evidence := c.observer.DNSKEYEvidence
	if w.Kind == model.KindSplit && w.ParentMode == parentModeInitial {
		evidence = c.observer.AuthoritativeDNSKEYEvidence
	}
	if _, err := evidence(ctx, zone.Name, publishedKeys(keys)...); err != nil {
		return fmt.Errorf("exact DNSKEY evidence missing immediately before parent write: %w", err)
	}
	if err := checkSignature(ctx, zone.Name, newKey); err != nil {
		return fmt.Errorf("new KSK signature missing: %w", err)
	}
	if w.Kind == model.KindSplit {
		checkOldSigner := c.observer.RRSIGBy
		if w.ParentMode == parentModeInitial {
			checkOldSigner = c.observer.AuthoritativeRRSIGBy
		}
		if err := checkOldSigner(ctx, zone.Name, old); err != nil {
			return fmt.Errorf("old CSK zone signature missing immediately before parent write: %w", err)
		}
	}
	oldData, err := dnsprobe.DNSSECDataForKey(zone.Name, old)
	if err != nil {
		return err
	}
	newData, err := dnsprobe.DNSSECDataForKey(zone.Name, newKey)
	if err != nil {
		return err
	}
	remote, err := c.registrar.DomainDNSSEC(ctx, zone.Name)
	if err != nil {
		return err
	}
	if remote.Enabled && sameMaterial(remote.Data, []model.DNSSECData{newData}) {
		return c.transition(w, model.PhaseWaitParentRemove, c.clock.Now(), func(x *model.Workflow) { x.EvidenceAt = time.Time{} })
	}
	if w.Kind == model.KindSplit && w.ParentMode == parentModeInitial {
		if remote.Enabled || len(remote.Data) != 0 {
			return c.block(zone.Name, w.Kind, "InternetX initial DNSSEC state changed before write")
		}
		if err := c.observer.NoDSEvidence(ctx, zone.Name); err != nil {
			return c.block(zone.Name, w.Kind, fmt.Sprintf("parent DS appeared before initial InternetX write: %v", err))
		}
	} else if !remote.Enabled || !sameMaterial(remote.Data, []model.DNSSECData{oldData}) {
		return c.block(zone.Name, w.Kind, "InternetX material is not the exact active old KSK/CSK")
	}
	if !w.RegistrarAttemptedAt.IsZero() {
		if c.clock.Now().Sub(w.RegistrarAttemptedAt) >= 24*time.Hour {
			return c.block(zone.Name, w.Kind, "ambiguous InternetX write did not converge within 24h; manual reconciliation required")
		}
		return fmt.Errorf("InternetX write outcome is ambiguous; waiting for read-back without resubmitting")
	}
	attemptedAt := c.clock.Now()
	if err := c.store.Update(func(s *model.State) error {
		x := s.Workflows[model.WorkflowKey(w.Zone, w.Kind)]
		x.RegistrarAttemptedAt = attemptedAt
		s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = x
		return nil
	}); err != nil {
		return err
	}
	job, err := c.registrar.UpdateDNSSEC(ctx, zone.Name, []model.DNSSECData{newData}, w.RegistrarCTID)
	if err != nil {
		return err
	}
	return c.transition(w, model.PhaseWaitParentRemove, c.clock.Now(), func(x *model.Workflow) {
		x.RegistrarSTID = job.STID
		x.RegistrarJobID = job.ID
		x.RegistrarJobStatus = job.Status
		x.EvidenceAt = time.Time{}
	})
}

func (c *Controller) waitParentReplace(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	if w.Kind == model.KindSplit {
		if err := validatePrepublishInventory(zone.Name, keys, w); err != nil {
			return c.block(zone.Name, w.Kind, fmt.Sprintf("split inventory drifted during parent wait; full DNSKEY prepublication recovery required: %v", err))
		}
	}
	_, newKey, err := recordedKeys(keys, w.OldKeyID, w.NewKeyID)
	if err != nil {
		return err
	}
	if w.RegistrarJobID > 0 && !jobSucceeded(w.RegistrarJobStatus) {
		status, err := c.registrar.JobStatus(ctx, w.RegistrarJobID)
		if err != nil {
			return err
		}
		if jobFailed(status) {
			return c.block(zone.Name, w.Kind, fmt.Sprintf("InternetX job %d finished with %s", w.RegistrarJobID, status))
		}
		if !jobSucceeded(status) {
			return fmt.Errorf("InternetX job %d is %s", w.RegistrarJobID, status)
		}
		return c.transition(w, model.PhaseWaitParentRemove, c.clock.Now(), func(x *model.Workflow) { x.RegistrarJobStatus = status })
	}
	ttl, err := c.observer.AuthoritativeDSEvidence(ctx, zone.Name, []model.Key{newKey})
	if err != nil {
		return err
	}
	if w.EvidenceAt.IsZero() {
		wait := maxDuration(ttl, c.cfg.Rotation.MinimumParentWait) + c.cfg.Controller.PropagationMargin
		return c.transition(w, model.PhaseWaitParentRemove, c.clock.Now().Add(wait), func(x *model.Workflow) { x.ParentDSTTL = int64(ttl / time.Second); x.EvidenceAt = c.clock.Now() })
	}
	if err := c.observer.DSEvidence(ctx, zone.Name, []model.Key{newKey}); err != nil {
		return err
	}
	if !newKey.Active || !newKey.Published {
		return c.block(zone.Name, w.Kind, "new KSK is not active and published after parent wait")
	}
	if _, err := c.observer.DNSKEYEvidence(ctx, zone.Name, publishedKeys(keys)...); err != nil {
		return fmt.Errorf("new KSK DNSKEY evidence missing after parent wait: %w", err)
	}
	if err := c.observer.DNSKEYRRSIGBy(ctx, zone.Name, newKey); err != nil {
		return fmt.Errorf("new KSK signature missing after parent wait: %w", err)
	}
	next := model.PhaseDeactivateOld
	if w.Kind == model.KindSplit {
		next = model.PhaseActivateNew
	}
	return c.transition(w, next, c.clock.Now(), func(x *model.Workflow) { x.EvidenceAt = time.Time{} })
}

func (c *Controller) waitRetire(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	_, newKey, err := recordedKeys(keys, w.OldKeyID, w.NewKeyID)
	if err != nil {
		return err
	}
	signer := newKey
	if w.Kind == model.KindSplit {
		var ok bool
		signer, ok = byID(keys, w.NewZSKID)
		if !ok {
			return c.block(zone.Name, w.Kind, "new ZSK missing at retirement")
		}
	}
	if err := c.observer.RRSIGBy(ctx, zone.Name, signer); err != nil {
		return err
	}
	return c.transition(w, model.PhaseDeleteOld, c.clock.Now(), nil)
}

func (c *Controller) deleteOld(ctx context.Context, zone model.Zone, keys []model.Key, w model.Workflow) error {
	newKey, ok := byID(keys, w.NewKeyID)
	if !ok || !newKey.Active || !newKey.Published {
		return c.block(zone.Name, w.Kind, "active and published replacement key missing")
	}
	old, exists := byID(keys, w.OldKeyID)
	dnskeys := []model.Key{newKey}
	if exists {
		dnskeys = append(dnskeys, old)
	}
	if w.Kind == model.KindKSK || w.Kind == model.KindSplit {
		if err := c.observer.DNSKEYRRSIGBy(ctx, zone.Name, newKey); err != nil {
			return err
		}
		if err := c.observer.DSEvidence(ctx, zone.Name, []model.Key{newKey}); err != nil {
			return err
		}
		if _, err := c.observer.AuthoritativeDSEvidence(ctx, zone.Name, []model.Key{newKey}); err != nil {
			return err
		}
	}
	switch w.Kind {
	case model.KindSplit:
		z, ok := byID(keys, w.NewZSKID)
		if !ok || !z.Active || !z.Published {
			return c.block(zone.Name, w.Kind, "active and published replacement ZSK missing")
		}
		if err := c.observer.RRSIGBy(ctx, zone.Name, z); err != nil {
			return err
		}
		dnskeys = append(dnskeys, z)
	case model.KindZSK:
		if err := c.observer.RRSIGBy(ctx, zone.Name, newKey); err != nil {
			return err
		}
	}
	if _, err := c.observer.DNSKEYEvidence(ctx, zone.Name, dnskeys...); err != nil {
		return fmt.Errorf("replacement DNSKEY evidence missing before deletion: %w", err)
	}
	if exists {
		if old.Active {
			return c.block(zone.Name, w.Kind, "refusing to delete active old key")
		}
		if err := c.pdns.DeleteKey(ctx, zone.ID, old.ID); err != nil {
			return err
		}
	}
	return c.complete(w)
}

func jobSucceeded(status string) bool {
	switch strings.ToUpper(status) {
	case "SUCCESS", "SUCCEEDED", "DONE", "COMPLETED":
		return true
	default:
		return false
	}
}

func jobFailed(status string) bool {
	switch strings.ToUpper(status) {
	case "FAILED", "FAILURE", "ERROR", "CANCELED", "CANCELLED":
		return true
	default:
		return false
	}
}

func (c *Controller) complete(w model.Workflow) error {
	now := c.clock.Now()
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", w.Zone, w.Kind, now.UTC().Format(time.RFC3339Nano))))
	eventID := fmt.Sprintf("dnssec-%x", sum[:16])
	return c.store.Update(func(s *model.State) error {
		k := model.WorkflowKey(w.Zone, w.Kind)
		x := s.Workflows[k]
		last := x.LastCompletedAt
		x = model.Workflow{Zone: w.Zone, Kind: w.Kind, Phase: model.PhaseIdle, LastCompletedAt: now}
		if w.Kind == model.KindEnroll {
			x.ZoneID = w.ZoneID
			x.NewKeyID = w.NewKeyID
			x.NewZSKID = w.NewZSKID
			x.DiscoveredAt = w.DiscoveredAt
			x.KeysetFingerprint = w.KeysetFingerprint
			x.EnrollmentDisposition = "enrolled"
			for _, role := range []model.Kind{model.KindKSK, model.KindZSK} {
				roleKey := model.WorkflowKey(w.Zone, role)
				roleWorkflow := s.Workflows[roleKey]
				roleWorkflow.Zone = w.Zone
				roleWorkflow.Kind = role
				roleWorkflow.Phase = model.PhaseIdle
				roleWorkflow.LastCompletedAt = now
				s.Workflows[roleKey] = roleWorkflow
			}
		}
		if now.Before(last) {
			x.LastCompletedAt = last
		}
		s.Workflows[k] = x
		if c.cfg.Notifications.LMTP.Enabled {
			s.Notifications[eventID] = model.Notification{ID: eventID, Event: "completed", Zone: w.Zone, Kind: w.Kind, CompletedAt: now, OldKeyID: w.OldKeyID, NewKeyID: w.NewKeyID, NewZSKID: w.NewZSKID, RegistrarSTID: w.RegistrarSTID, NextAttemptAt: now}
		}
		return nil
	})
}

func (c *Controller) deliverNotifications(ctx context.Context) error {
	now := c.clock.Now()
	stateSnapshot := c.store.Snapshot()
	var expired []string
	for id, event := range stateSnapshot.Notifications {
		if !event.DeliveredAt.IsZero() && now.Sub(event.DeliveredAt) > c.cfg.Controller.IdempotencyRetention {
			expired = append(expired, id)
		}
	}
	if len(expired) > 0 {
		if err := c.store.Update(func(s *model.State) error {
			for _, id := range expired {
				delete(s.Notifications, id)
			}
			return nil
		}); err != nil {
			return err
		}
		stateSnapshot = c.store.Snapshot()
	}
	if !c.cfg.Notifications.LMTP.Enabled {
		return nil
	}
	ids := make([]string, 0, len(stateSnapshot.Notifications))
	for id, event := range stateSnapshot.Notifications {
		if event.DeliveredAt.IsZero() && (event.NextAttemptAt.IsZero() || !now.Before(event.NextAttemptAt)) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	var errs []error
	for _, id := range ids {
		event := stateSnapshot.Notifications[id]
		err := c.notifier.Send(ctx, event)
		if updateErr := c.store.Update(func(s *model.State) error {
			current, ok := s.Notifications[id]
			if !ok || !current.DeliveredAt.IsZero() {
				return nil
			}
			if err == nil {
				current.DeliveredAt = now
				current.LastError = ""
				current.NextAttemptAt = time.Time{}
			} else {
				current.Attempts++
				current.LastError = err.Error()
				current.NextAttemptAt = now.Add(time.Minute * time.Duration(1<<min(current.Attempts, 8)))
			}
			s.Notifications[id] = current
			return nil
		}); updateErr != nil {
			errs = append(errs, updateErr)
		} else if err != nil {
			errs = append(errs, fmt.Errorf("notification %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) transition(w model.Workflow, phase model.Phase, next time.Time, mutate func(*model.Workflow)) error {
	return c.store.Update(func(s *model.State) error {
		k := model.WorkflowKey(w.Zone, w.Kind)
		x := s.Workflows[k]
		x.Phase = phase
		x.PhaseStartedAt = c.clock.Now()
		x.NextActionAt = next
		x.LastError = ""
		x.Attempts = 0
		if mutate != nil {
			mutate(&x)
		}
		s.Workflows[k] = x
		return nil
	})
}
func (c *Controller) recordRetry(w model.Workflow, cause error) error {
	return c.store.Update(func(s *model.State) error {
		k := model.WorkflowKey(w.Zone, w.Kind)
		x := s.Workflows[k]
		x.Attempts++
		x.LastError = cause.Error()
		backoff := time.Minute * time.Duration(1<<min(x.Attempts, 8))
		x.NextActionAt = c.clock.Now().Add(backoff)
		s.Workflows[k] = x
		return nil
	})
}
func (c *Controller) block(zone string, kind model.Kind, reason string) error {
	_ = c.store.Update(func(s *model.State) error {
		k := model.WorkflowKey(zone, kind)
		x := s.Workflows[k]
		x.Zone = zone
		x.Kind = kind
		x.Phase = model.PhaseBlocked
		x.LastError = reason
		x.NextActionAt = time.Time{}
		s.Workflows[k] = x
		if kind == model.KindEnroll && c.cfg.Notifications.LMTP.Enabled {
			sum := sha256.Sum256([]byte(zone + "|" + string(kind) + "|" + x.KeysetFingerprint + "|blocked"))
			eventID := fmt.Sprintf("dnssec-%x", sum[:16])
			if _, exists := s.Notifications[eventID]; !exists {
				s.Notifications[eventID] = model.Notification{ID: eventID, Event: "blocked", Zone: zone, Kind: kind, CompletedAt: c.clock.Now(), NewKeyID: x.NewKeyID, NewZSKID: x.NewZSKID, NextAttemptAt: c.clock.Now()}
			}
		}
		return nil
	})
	return errors.New(reason)
}

// ArmEnrollment establishes a one-time safety baseline. It is deliberately
// state-only: every currently DNSSEC-enabled zone receives a permanent idle
// enrollment tombstone before the global arm timestamp is committed.
func (c *Controller) ArmEnrollment(ctx context.Context, idem string) error {
	if c.cfg.Mode != "enforce" {
		return errors.New("controller is in observe mode")
	}
	if !c.cfg.Enrollment.Enabled || c.cfg.Enrollment.Scope != "all_selected" {
		return errors.New("automatic enrollment is not explicitly enabled for all_selected scope")
	}
	if len(idem) < 16 || len(idem) > 128 {
		return errors.New("idempotency key must be between 16 and 128 characters")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fingerprint := "enrollment-arm"
	st := c.store.Snapshot()
	if existing, ok := st.Idempotency[idem]; ok {
		if existing == fingerprint {
			return nil
		}
		return errors.New("idempotency key already used for a different request")
	}
	if !st.EnrollmentArmedAt.IsZero() {
		return errors.New("automatic enrollment is already armed")
	}
	zones, err := c.pdns.ListZones(ctx)
	if err != nil {
		return err
	}
	now := c.clock.Now()
	return c.store.Update(func(s *model.State) error {
		if !s.EnrollmentArmedAt.IsZero() {
			return errors.New("automatic enrollment is already armed")
		}
		for _, zone := range zones {
			if !zone.DNSSEC {
				continue
			}
			key := model.WorkflowKey(zone.Name, model.KindEnroll)
			if _, ok := s.Workflows[key]; !ok {
				s.Workflows[key] = model.Workflow{Zone: zone.Name, ZoneID: zone.ID, Kind: model.KindEnroll, Phase: model.PhaseIdle, LastCompletedAt: now, EnrollmentDisposition: "baseline"}
			}
		}
		s.EnrollmentArmedAt = now
		s.Idempotency[idem] = fingerprint
		return nil
	})
}

// Trigger validates and persists a confirmed manual rotation request.
func (c *Controller) Trigger(ctx context.Context, kind model.Kind, zones []string, idem string) error {
	if c.cfg.Mode != "enforce" {
		return errors.New("controller is in observe mode")
	}
	if len(idem) < 16 || len(idem) > 128 {
		return errors.New("idempotency key must be between 16 and 128 characters")
	}
	normalized := append([]string(nil), zones...)
	for i := range normalized {
		normalized[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(normalized[i])), ".")
	}
	slices.Sort(normalized)
	normalized = slices.Compact(normalized)
	fingerprint := string(kind) + "|" + strings.Join(normalized, ",")
	st := c.store.Snapshot()
	if existing, ok := st.Idempotency[idem]; ok {
		if existing == fingerprint {
			return nil
		}
		return errors.New("idempotency key already used for a different request")
	}
	available, err := c.pdns.ListZones(ctx)
	if err != nil {
		return err
	}
	byName := map[string]model.Zone{}
	for _, z := range available {
		byName[z.Name] = z
		byName[strings.TrimSuffix(z.Name, ".")] = z
	}
	var canonical []string
	for _, name := range normalized {
		z, ok := byName[name]
		if !ok || !z.DNSSEC {
			return fmt.Errorf("zone %s is absent or not DNSSEC-enabled", name)
		}
		if !c.selected(z.Name) {
			return fmt.Errorf("zone %s is outside the configured rotation scope", name)
		}
		keys, err := c.pdns.ListKeys(ctx, z.ID)
		if err != nil {
			return err
		}
		scheme := keyScheme(keys)
		if kind == model.KindSplit && scheme != "csk" {
			return fmt.Errorf("zone %s is not a CSK zone", name)
		}
		if kind != model.KindSplit && scheme != "split" {
			return fmt.Errorf("zone %s is not split KSK/ZSK", name)
		}
		canonical = append(canonical, z.Name)
	}
	now := c.clock.Now()
	return c.store.Update(func(s *model.State) error {
		if existing, ok := s.Idempotency[idem]; ok {
			if existing == fingerprint {
				return nil
			}
			return errors.New("idempotency key conflict")
		}
		for _, zone := range canonical {
			for _, w := range s.Workflows {
				if w.Zone == zone && w.Active() {
					return fmt.Errorf("zone %s already has active %s workflow", zone, w.Kind)
				}
			}
		}
		for _, zone := range canonical {
			k := model.WorkflowKey(zone, kind)
			w := s.Workflows[k]
			w.Zone = zone
			w.Kind = kind
			w.Phase = model.PhasePrepublish
			w.PhaseStartedAt = now
			w.NextActionAt = now
			w.LastError = ""
			w.Attempts = 0
			w.Manual = true
			w.IdempotencyKey = idem
			s.Workflows[k] = w
		}
		s.Idempotency[idem] = fingerprint
		return nil
	})
}

// Resume performs a deliberately narrow recovery transition. It never writes
// to PowerDNS or the registrar: every live invariant is re-proven first, then
// all requested blocked workflows are moved atomically back to wait_publish.
func (c *Controller) Resume(ctx context.Context, kind model.Kind, zones []string, phase model.Phase, idem string) error {
	if c.cfg.Mode != "enforce" {
		return errors.New("controller is in observe mode")
	}
	if kind != model.KindSplit || phase != model.PhaseWaitPublish {
		return errors.New("only split workflows may be resumed to wait_publish")
	}
	if len(idem) < 16 || len(idem) > 128 {
		return errors.New("idempotency key must be between 16 and 128 characters")
	}

	normalized := append([]string(nil), zones...)
	for i := range normalized {
		normalized[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(normalized[i])), ".")
	}
	slices.Sort(normalized)
	normalized = slices.Compact(normalized)
	if len(normalized) == 0 || len(normalized) > 100 {
		return errors.New("between one and 100 zones are required")
	}
	fingerprint := "resume|" + string(kind) + "|" + string(phase) + "|" + strings.Join(normalized, ",")

	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.store.Snapshot()
	if existing, ok := st.Idempotency[idem]; ok {
		if existing == fingerprint {
			return nil
		}
		return errors.New("idempotency key already used for a different request")
	}

	available, err := c.pdns.ListZones(ctx)
	if err != nil {
		return err
	}
	byName := make(map[string]model.Zone, len(available)*2)
	for _, zone := range available {
		byName[strings.ToLower(zone.Name)] = zone
		byName[strings.TrimSuffix(strings.ToLower(zone.Name), ".")] = zone
	}

	type recovery struct {
		zone     string
		workflow model.Workflow
	}
	recoveries := make([]recovery, 0, len(normalized))
	for _, name := range normalized {
		zone, ok := byName[name]
		if !ok || !zone.DNSSEC {
			return fmt.Errorf("zone %s is absent or not DNSSEC-enabled", name)
		}
		if !c.selected(zone.Name) {
			return fmt.Errorf("zone %s is outside the configured rotation scope", name)
		}
		w, ok := st.Workflows[model.WorkflowKey(zone.Name, kind)]
		if !ok || w.Phase != model.PhaseBlocked {
			return fmt.Errorf("zone %s has no blocked split workflow", name)
		}
		if w.ParentMode != parentModeInitial || w.OldKeyID == 0 || w.NewKeyID == 0 || w.NewZSKID == 0 {
			return fmt.Errorf("zone %s is not an initialized initial-delegation split workflow", name)
		}
		if w.OldKeyID == w.NewKeyID || w.OldKeyID == w.NewZSKID || w.NewKeyID == w.NewZSKID {
			return fmt.Errorf("zone %s does not record three distinct key IDs", name)
		}
		if !w.RegistrarAttemptedAt.IsZero() || w.RegistrarJobID != 0 || w.RegistrarCTID != "" || w.RegistrarSTID != "" || w.RegistrarJobStatus != "" {
			return fmt.Errorf("zone %s already records a registrar mutation attempt", name)
		}
		keys, err := c.pdns.ListKeys(ctx, zone.ID)
		if err != nil {
			return err
		}
		if err := validatePrepublishInventory(zone.Name, keys, w); err != nil {
			return fmt.Errorf("zone %s inventory cannot be resumed: %w", name, err)
		}
		remote, err := c.registrar.DomainDNSSEC(ctx, zone.Name)
		if err != nil {
			return err
		}
		if remote.Enabled || len(remote.Data) != 0 {
			return fmt.Errorf("zone %s registrar DNSSEC state is not disabled-empty", name)
		}
		if err := c.observer.NoDSEvidence(ctx, zone.Name); err != nil {
			return fmt.Errorf("zone %s parent DS absence is not proven: %w", name, err)
		}
		recoveries = append(recoveries, recovery{zone: zone.Name, workflow: w})
	}

	now := c.clock.Now()
	return c.store.Update(func(s *model.State) error {
		if existing, ok := s.Idempotency[idem]; ok {
			if existing == fingerprint {
				return nil
			}
			return errors.New("idempotency key conflict")
		}
		for _, item := range recoveries {
			key := model.WorkflowKey(item.zone, kind)
			current, ok := s.Workflows[key]
			if !ok || current.Phase != model.PhaseBlocked || current.OldKeyID != item.workflow.OldKeyID || current.NewKeyID != item.workflow.NewKeyID || current.NewZSKID != item.workflow.NewZSKID {
				return fmt.Errorf("zone %s workflow changed during resume validation", item.zone)
			}
		}
		for _, item := range recoveries {
			key := model.WorkflowKey(item.zone, kind)
			w := s.Workflows[key]
			w.Phase = model.PhaseWaitPublish
			w.PhaseStartedAt = now
			w.NextActionAt = now
			w.EvidenceAt = time.Time{}
			w.DNSKEYTTL = 0
			w.LastError = ""
			w.Attempts = 0
			s.Workflows[key] = w
		}
		s.Idempotency[idem] = fingerprint
		return nil
	})
}

// Plan returns the ordered mutation summary for a rotation kind.
func (c *Controller) Plan(kind model.Kind, zones []string) Plan {
	m := map[model.Kind][]string{model.KindZSK: {"publish inactive ZSK", "observe and wait authoritative DNSKEY TTL", "activate new ZSK", "cryptographically prove new zone signatures", "deactivate old ZSK", "wait persisted pre-switch zone TTL", "delete old ZSK"}, model.KindKSK: {"publish active KSK and prove double DNSKEY signatures", "observe and wait authoritative DNSKEY TTL", "replace InternetX material with new-only KSK", "observe authoritative parent and wait full DS TTL", "verify exact new-only DS through validating resolvers", "deactivate and delete old KSK"}, model.KindSplit: {"publish active KSK and inactive ZSK", "prove and wait DNSKEY propagation", "replace parent material and wait DS TTL", "activate ZSK and prove overlapping CSK/ZSK signatures", "wait zone TTL, deactivate CSK, wait zone TTL again", "verify and delete CSK"}}
	return Plan{Kind: kind, Zones: zones, Mutations: m[kind]}
}

// Zones returns managed zone and workflow status without exposing key material.
func (c *Controller) Zones(ctx context.Context) ([]ZoneStatus, error) {
	zones, err := c.pdns.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	st := c.store.Snapshot()
	var out []ZoneStatus
	seen := make(map[string]bool, len(zones))
	for _, z := range zones {
		enrollment := st.Workflows[model.WorkflowKey(z.Name, model.KindEnroll)]
		showEnrollmentException := enrollment.Active() || enrollment.Phase == model.PhaseBlocked
		if (!z.DNSSEC || !c.selected(z.Name)) && !showEnrollmentException {
			continue
		}
		seen[z.Name] = true
		keys, err := c.pdns.ListKeys(ctx, z.ID)
		if err != nil {
			return nil, err
		}
		zs := ZoneStatus{Zone: z.Name, DNSSEC: true, Scheme: keyScheme(keys), EnrollmentStatus: "disarmed"}
		if zs.Scheme == "csk" {
			zs.BlockedReason = "explicit confirmed CSK-to-split migration required"
		}
		for _, w := range st.Workflows {
			if w.Zone == z.Name {
				zs.Workflows = append(zs.Workflows, w)
				if w.Kind == model.KindEnroll {
					zs.Managed = w.Phase == model.PhaseIdle && w.EnrollmentDisposition != "ineligible"
					switch w.Phase {
					case model.PhaseIdle:
						zs.EnrollmentStatus = w.EnrollmentDisposition
						if zs.EnrollmentStatus == "" {
							zs.EnrollmentStatus = "managed"
						}
					case model.PhaseEnrollDiscovered:
						zs.EnrollmentStatus = "candidate"
					case model.PhaseEnrollWaitPublish:
						zs.EnrollmentStatus = "waiting"
					case model.PhaseEnrollParentAdd:
						zs.EnrollmentStatus = "registrar_pending"
					case model.PhaseEnrollWaitParent:
						zs.EnrollmentStatus = "parent_wait"
					case model.PhaseBlocked:
						zs.EnrollmentStatus = "blocked"
					}
				}
				if w.Phase == model.PhaseBlocked {
					zs.BlockedReason = w.LastError
				}
			}
		}
		slices.SortFunc(zs.Workflows, func(a, b model.Workflow) int { return strings.Compare(string(a.Kind), string(b.Kind)) })
		out = append(out, zs)
	}
	for _, workflow := range st.Workflows {
		if workflow.Kind != model.KindEnroll || !workflow.Active() || seen[workflow.Zone] {
			continue
		}
		status := "blocked"
		if workflow.Phase != model.PhaseBlocked {
			status = "candidate"
		}
		out = append(out, ZoneStatus{Zone: workflow.Zone, DNSSEC: false, Scheme: "unknown", Managed: false, EnrollmentStatus: status, BlockedReason: workflow.LastError, Workflows: []model.Workflow{workflow}})
	}
	slices.SortFunc(out, func(a, b ZoneStatus) int { return strings.Compare(a.Zone, b.Zone) })
	return out, nil
}

// Status returns aggregate readiness and workflow counts.
func (c *Controller) Status(ctx context.Context) (Status, error) {
	z, err := c.Zones(ctx)
	if err != nil {
		return Status{Mode: c.cfg.Mode}, err
	}
	b := 0
	for _, x := range z {
		if x.BlockedReason != "" {
			b++
		}
	}
	pending, enrolling, managed := 0, 0, 0
	snapshot := c.store.Snapshot()
	for _, workflow := range snapshot.Workflows {
		if workflow.Kind != model.KindEnroll {
			continue
		}
		if workflow.Active() {
			enrolling++
		} else if workflow.EnrollmentDisposition != "ineligible" {
			managed++
		}
	}
	for _, event := range snapshot.Notifications {
		if event.DeliveredAt.IsZero() {
			pending++
		}
	}
	return Status{Mode: c.cfg.Mode, Ready: true, Zones: len(z), Blocked: b, EnrollmentArmed: !snapshot.EnrollmentArmedAt.IsZero(), Enrolling: enrolling, Managed: managed, PendingNotifications: pending}, nil
}

// Audit compares active local public KSK or CSK material with registrar state.
func (c *Controller) Audit(ctx context.Context) ([]AuditResult, error) {
	zones, err := c.pdns.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	var out []AuditResult
	for _, z := range zones {
		if !z.DNSSEC || !c.selected(z.Name) {
			continue
		}
		r := AuditResult{Zone: z.Name}
		keys, err := c.pdns.ListKeys(ctx, z.ID)
		if err != nil {
			r.Error = err.Error()
			out = append(out, r)
			continue
		}
		r.Scheme = keyScheme(keys)
		typ := "ksk"
		if r.Scheme == "csk" {
			typ = "csk"
		}
		key, err := exactlyOneActive(keys, typ)
		if err != nil {
			r.Error = err.Error()
			out = append(out, r)
			continue
		}
		expected, err := dnsprobe.DNSSECDataForKey(z.Name, key)
		if err != nil {
			r.Error = err.Error()
			out = append(out, r)
			continue
		}
		remote, err := c.registrar.DomainDNSSEC(ctx, z.Name)
		if err != nil {
			r.Error = err.Error()
			out = append(out, r)
			continue
		}
		r.RegistrarMatch = remote.Enabled && sameMaterial(remote.Data, []model.DNSSECData{expected})
		if !r.RegistrarMatch {
			r.Error = "InternetX material differs from active local KSK/CSK"
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b AuditResult) int { return strings.Compare(a.Zone, b.Zone) })
	return out, nil
}

func (c *Controller) selected(zone string) bool {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	for _, x := range c.cfg.Rotation.ExcludeZones {
		if strings.TrimSuffix(strings.ToLower(x), ".") == zone {
			return false
		}
	}
	if len(c.cfg.Rotation.IncludeZones) == 0 {
		return true
	}
	for _, x := range c.cfg.Rotation.IncludeZones {
		if strings.TrimSuffix(strings.ToLower(x), ".") == zone {
			return true
		}
	}
	return false
}

func (c *Controller) selectedEnrollment(zone string) bool {
	if c.cfg.Enrollment.Scope != "all_selected" || !c.selected(zone) {
		return false
	}
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	for _, item := range c.cfg.Enrollment.ExcludeZones {
		if strings.TrimSuffix(strings.ToLower(item), ".") == zone {
			return false
		}
	}
	if len(c.cfg.Enrollment.IncludeZones) == 0 {
		return true
	}
	for _, item := range c.cfg.Enrollment.IncludeZones {
		if strings.TrimSuffix(strings.ToLower(item), ".") == zone {
			return true
		}
	}
	return false
}
func keyScheme(keys []model.Key) string {
	a := map[string]int{}
	for _, k := range keys {
		if k.Active {
			a[k.KeyType]++
		}
	}
	if a["ksk"] == 1 && a["zsk"] == 1 && a["csk"] == 0 {
		return "split"
	}
	if a["csk"] == 1 && a["ksk"] == 0 && a["zsk"] == 0 {
		return "csk"
	}
	return "unknown"
}
func exactlyOneActive(keys []model.Key, typ string) (model.Key, error) {
	var a []model.Key
	for _, k := range keys {
		if k.KeyType == typ && k.Active {
			a = append(a, k)
		}
	}
	if len(a) != 1 {
		return model.Key{}, fmt.Errorf("expected one active %s, got %d", typ, len(a))
	}
	return a[0], nil
}
func byID(keys []model.Key, id int) (model.Key, bool) {
	for _, k := range keys {
		if k.ID == id {
			return k, true
		}
	}
	return model.Key{}, false
}
func recordedKeys(keys []model.Key, oldID, newID int) (model.Key, model.Key, error) {
	old, ok := byID(keys, oldID)
	if !ok {
		return model.Key{}, model.Key{}, fmt.Errorf("recorded old key %d missing", oldID)
	}
	n, ok := byID(keys, newID)
	if !ok {
		return model.Key{}, model.Key{}, fmt.Errorf("recorded new key %d missing", newID)
	}
	return old, n, nil
}
func publishedKeys(keys []model.Key) []model.Key {
	out := make([]model.Key, 0, len(keys))
	for _, key := range keys {
		if key.Published {
			out = append(out, key)
		}
	}
	return out
}

func validateEnrollmentInventory(zone string, keys []model.Key, expectedKSK, expectedZSK int, expectedFingerprint string, allowedAlgorithms []string) (model.Key, model.Key, string, error) {
	var ksk, zsk []model.Key
	for _, key := range keys {
		if !key.Active && !key.Published {
			continue
		}
		if !key.Active || !key.Published {
			return model.Key{}, model.Key{}, "", fmt.Errorf("key %d is active/published only partially", key.ID)
		}
		switch key.KeyType {
		case "ksk":
			ksk = append(ksk, key)
		case "zsk":
			zsk = append(zsk, key)
		default:
			return model.Key{}, model.Key{}, "", fmt.Errorf("unexpected active or published key %d (%s)", key.ID, key.KeyType)
		}
	}
	if len(ksk) != 1 || len(zsk) != 1 || ksk[0].ID == zsk[0].ID {
		return model.Key{}, model.Key{}, "", fmt.Errorf("expected exactly one distinct active/published KSK and ZSK")
	}
	if expectedKSK != 0 && ksk[0].ID != expectedKSK {
		return model.Key{}, model.Key{}, "", fmt.Errorf("KSK id changed from %d to %d", expectedKSK, ksk[0].ID)
	}
	if expectedZSK != 0 && zsk[0].ID != expectedZSK {
		return model.Key{}, model.Key{}, "", fmt.Errorf("ZSK id changed from %d to %d", expectedZSK, zsk[0].ID)
	}
	kdata, err := validatedKeyRole(zone, ksk[0], "ksk", false)
	if err != nil {
		return model.Key{}, model.Key{}, "", err
	}
	zdata, err := validatedKeyRole(zone, zsk[0], "zsk", false)
	if err != nil {
		return model.Key{}, model.Key{}, "", err
	}
	if kdata.Algorithm != zdata.Algorithm {
		return model.Key{}, model.Key{}, "", fmt.Errorf("KSK and ZSK algorithms differ")
	}
	if err := validateAlgorithmLabel(ksk[0].Algorithm, kdata.Algorithm); err != nil {
		return model.Key{}, model.Key{}, "", err
	}
	if err := validateAlgorithmLabel(zsk[0].Algorithm, zdata.Algorithm); err != nil {
		return model.Key{}, model.Key{}, "", err
	}
	allowed := false
	for _, label := range allowedAlgorithms {
		if strings.EqualFold(strings.TrimSpace(label), ksk[0].Algorithm) {
			allowed = true
			break
		}
	}
	if !allowed {
		return model.Key{}, model.Key{}, "", fmt.Errorf("algorithm %q is not allowed for automatic enrollment", ksk[0].Algorithm)
	}
	canonical := fmt.Sprintf("ksk|%d|%d|%d|%s|zsk|%d|%d|%d|%s", ksk[0].ID, kdata.Protocol, kdata.Algorithm, kdata.PublicKey, zsk[0].ID, zdata.Protocol, zdata.Algorithm, zdata.PublicKey)
	sum := sha256.Sum256([]byte(canonical))
	fingerprint := fmt.Sprintf("sha256:%x", sum[:])
	if expectedFingerprint != "" && fingerprint != expectedFingerprint {
		return model.Key{}, model.Key{}, "", fmt.Errorf("public keyset fingerprint changed")
	}
	return ksk[0], zsk[0], fingerprint, nil
}

func dnssecPayloadHash(data model.DNSSECData) string {
	canonical := fmt.Sprintf("%d|%d|%d|%s", data.Flags, data.Protocol, data.Algorithm, data.PublicKey)
	sum := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("sha256:%x", sum[:])
}
func validatePrepublishInventory(zone string, keys []model.Key, w model.Workflow) error {
	if w.OldKeyID == 0 || w.NewKeyID == 0 || w.OldKeyID == w.NewKeyID {
		return errors.New("recorded old and new key IDs must be non-zero and distinct")
	}
	if w.Kind == model.KindSplit && (w.NewZSKID == 0 || w.OldKeyID == w.NewZSKID || w.NewKeyID == w.NewZSKID) {
		return errors.New("split workflow must record three distinct key IDs")
	}
	old, newKey, err := recordedKeys(keys, w.OldKeyID, w.NewKeyID)
	if err != nil {
		return err
	}
	wantOldType := string(w.Kind)
	if w.Kind == model.KindSplit {
		wantOldType = "csk"
	}
	oldData, err := validatedKeyRole(zone, old, wantOldType, false)
	if err != nil {
		return fmt.Errorf("recorded old key role: %w", err)
	}
	if !old.Active || !old.Published {
		return fmt.Errorf("recorded old %s is not active and published", wantOldType)
	}
	wantNewType := string(w.Kind)
	wantNewActive := w.Kind == model.KindKSK || w.Kind == model.KindSplit
	if w.Kind == model.KindSplit {
		wantNewType = "ksk"
	}
	newData, err := validatedKeyRole(zone, newKey, wantNewType, w.Kind == model.KindSplit)
	if err != nil {
		return fmt.Errorf("recorded new key role: %w", err)
	}
	if newData.Algorithm != oldData.Algorithm {
		return fmt.Errorf("recorded new key algorithm %d differs from old key algorithm %d", newData.Algorithm, oldData.Algorithm)
	}
	if newKey.Active != wantNewActive || !newKey.Published {
		return fmt.Errorf("recorded new %s has unexpected active/published state", wantNewType)
	}
	allowed := map[int]bool{old.ID: true, newKey.ID: true}
	if w.Kind == model.KindSplit {
		zsk, ok := byID(keys, w.NewZSKID)
		if !ok {
			return fmt.Errorf("recorded new ZSK missing")
		}
		zskData, err := validatedKeyRole(zone, zsk, "zsk", true)
		if err != nil {
			return fmt.Errorf("recorded new ZSK role: %w", err)
		}
		if zskData.Algorithm != oldData.Algorithm {
			return fmt.Errorf("recorded new ZSK algorithm %d differs from old key algorithm %d", zskData.Algorithm, oldData.Algorithm)
		}
		if zsk.Active || !zsk.Published {
			return fmt.Errorf("recorded new ZSK is not inactive and published")
		}
		allowed[zsk.ID] = true
	} else {
		companionType := "ksk"
		if w.Kind == model.KindKSK {
			companionType = "zsk"
		}
		companion, err := exactlyOneActive(keys, companionType)
		if err != nil || !companion.Published {
			return fmt.Errorf("expected one active and published companion %s", companionType)
		}
		allowed[companion.ID] = true
	}
	for _, key := range keys {
		if (key.Active || key.Published) && !allowed[key.ID] {
			return fmt.Errorf("unexpected active or published key %d (%s)", key.ID, key.KeyType)
		}
	}
	return nil
}

func validateActiveSplitInventory(zone string, keys []model.Key, w model.Workflow) error {
	return validateSplitMutationInventory(zone, keys, w, true)
}

func validateDeactivatedSplitInventory(zone string, keys []model.Key, w model.Workflow) error {
	return validateSplitMutationInventory(zone, keys, w, false)
}

func validateSplitMutationInventory(zone string, keys []model.Key, w model.Workflow, oldActive bool) error {
	if w.Kind != model.KindSplit || w.OldKeyID == 0 || w.NewKeyID == 0 || w.NewZSKID == 0 || w.OldKeyID == w.NewKeyID || w.OldKeyID == w.NewZSKID || w.NewKeyID == w.NewZSKID {
		return errors.New("active split workflow must record three distinct key IDs")
	}
	old, newKSK, err := recordedKeys(keys, w.OldKeyID, w.NewKeyID)
	if err != nil {
		return err
	}
	newZSK, ok := byID(keys, w.NewZSKID)
	if !ok {
		return fmt.Errorf("recorded new ZSK %d missing", w.NewZSKID)
	}
	oldData, err := validatedKeyRole(zone, old, "ksk", true)
	if err != nil {
		return fmt.Errorf("recorded old CSK effective role: %w", err)
	}
	kskData, err := validatedKeyRole(zone, newKSK, "ksk", true)
	if err != nil {
		return fmt.Errorf("recorded new KSK role: %w", err)
	}
	zskData, err := validatedKeyRole(zone, newZSK, "zsk", true)
	if err != nil {
		return fmt.Errorf("recorded new ZSK role: %w", err)
	}
	if oldData.Algorithm != kskData.Algorithm || oldData.Algorithm != zskData.Algorithm {
		return fmt.Errorf("active split DNSKEY algorithms differ")
	}
	if old.Active != oldActive || !old.Published || !newKSK.Active || !newKSK.Published || !newZSK.Active || !newZSK.Published {
		return fmt.Errorf("split keys do not match expected old-active=%t post-activation state", oldActive)
	}
	allowed := map[int]bool{old.ID: true, newKSK.ID: true, newZSK.ID: true}
	for _, key := range keys {
		if (key.Active || key.Published) && !allowed[key.ID] {
			return fmt.Errorf("unexpected active or published key %d (%s)", key.ID, key.KeyType)
		}
	}
	return nil
}

// validateKeyRole treats DNSKEY flags as the cryptographic source of truth.
// PowerDNS can report a newly-created split KSK/ZSK as keytype "csk" while an
// active CSK still signs the zone. That transitional label is accepted only
// for the recorded new keys of an explicit split migration.
func validatedKeyRole(zone string, key model.Key, wantType string, allowTransitionalCSK bool) (model.DNSSECData, error) {
	wantFlags := uint16(256)
	if wantType == "ksk" || wantType == "csk" {
		wantFlags = 257
	}
	data, err := dnsprobe.DNSSECDataForKey(zone, key)
	if err != nil {
		return model.DNSSECData{}, fmt.Errorf("key %d DNSKEY is invalid: %w", key.ID, err)
	}
	if data.Protocol != 3 {
		return model.DNSSECData{}, fmt.Errorf("key %d has DNSKEY protocol %d, want 3", key.ID, data.Protocol)
	}
	if data.Flags != wantFlags {
		return model.DNSSECData{}, fmt.Errorf("key %d has DNSKEY flags %d, want %d for %s", key.ID, data.Flags, wantFlags, wantType)
	}
	if key.KeyType == wantType {
		return data, nil
	}
	if allowTransitionalCSK && key.KeyType == "csk" && (wantType == "ksk" || wantType == "zsk") {
		return data, nil
	}
	return model.DNSSECData{}, fmt.Errorf("key %d has PowerDNS keytype %q, want %q", key.ID, key.KeyType, wantType)
}

func validateAlgorithmLabel(label string, algorithm uint8) error {
	want, ok := dns.StringToAlgorithm[strings.ToUpper(strings.TrimSpace(label))]
	if !ok {
		return fmt.Errorf("unknown PowerDNS algorithm %q", label)
	}
	if want != algorithm {
		return fmt.Errorf("PowerDNS algorithm %q maps to %d but DNSKEY contains %d", label, want, algorithm)
	}
	return nil
}
func maxTTL(z model.Zone) time.Duration {
	var maximum uint32 = 86400
	for _, r := range z.RRsets {
		if r.TTL > maximum {
			maximum = r.TTL
		}
	}
	return time.Duration(maximum) * time.Second
}
func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
func sameMaterial(a, b []model.DNSSECData) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(x model.DNSSECData) string {
		return fmt.Sprintf("%d/%d/%d/%s", x.Flags, x.Protocol, x.Algorithm, strings.TrimSpace(x.PublicKey))
	}
	aa := make([]string, len(a))
	bb := make([]string, len(b))
	for i := range a {
		aa[i] = key(a[i])
	}
	for i := range b {
		bb[i] = key(b[i])
	}
	slices.Sort(aa)
	slices.Sort(bb)
	return slices.Equal(aa, bb)
}
