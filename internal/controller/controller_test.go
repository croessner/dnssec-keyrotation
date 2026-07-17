package controller

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/dnssec-keyrotation/internal/autodns"
	"github.com/croessner/dnssec-keyrotation/internal/config"
	"github.com/croessner/dnssec-keyrotation/internal/dnsprobe"
	"github.com/croessner/dnssec-keyrotation/internal/model"
	"github.com/croessner/dnssec-keyrotation/internal/pdns"
	"github.com/croessner/dnssec-keyrotation/internal/state"
)

type fakePDNS struct{}

func (fakePDNS) ListZones(context.Context) ([]model.Zone, error)       { return nil, nil }
func (fakePDNS) GetZone(context.Context, string) (model.Zone, error)   { return model.Zone{}, nil }
func (fakePDNS) ListKeys(context.Context, string) ([]model.Key, error) { return nil, nil }
func (fakePDNS) CreateKey(context.Context, string, string, string, bool) (model.Key, error) {
	return model.Key{}, nil
}
func (fakePDNS) SetKey(context.Context, string, model.Key, bool, bool) error { return nil }
func (fakePDNS) DeleteKey(context.Context, string, int) error                { return nil }

type fakeRegistrar struct {
	updates   int
	state     autodns.DomainDNSSECState
	updateErr error
}

func (f *fakeRegistrar) DomainDNSSEC(context.Context, string) (autodns.DomainDNSSECState, error) {
	return f.state, nil
}
func (f *fakeRegistrar) UpdateDNSSEC(context.Context, string, []model.DNSSECData, string) (autodns.Job, error) {
	f.updates++
	if f.updateErr != nil {
		return autodns.Job{}, f.updateErr
	}
	return autodns.Job{ID: 42, STID: "tx", Status: "RUNNING"}, nil
}
func (*fakeRegistrar) JobStatus(context.Context, int64) (string, error) { return "SUCCESS", nil }

type refusingObserver struct{ signatureChecks int }

func (*refusingObserver) DNSKEYEvidence(context.Context, string, ...model.Key) (time.Duration, error) {
	return time.Hour, nil
}
func (*refusingObserver) AuthoritativeDNSKEYEvidence(context.Context, string, ...model.Key) (time.Duration, error) {
	return time.Hour, nil
}
func (*refusingObserver) NoDSEvidence(context.Context, string) error            { return nil }
func (*refusingObserver) DSEvidence(context.Context, string, []model.Key) error { return nil }
func (*refusingObserver) AuthoritativeDSEvidence(context.Context, string, []model.Key) (time.Duration, error) {
	return time.Hour, nil
}
func (o *refusingObserver) RRSIGBy(context.Context, string, model.Key) error {
	return nil
}
func (o *refusingObserver) AuthoritativeRRSIGBy(context.Context, string, model.Key) error {
	return nil
}
func (o *refusingObserver) DNSKEYRRSIGBy(context.Context, string, model.Key) error {
	o.signatureChecks++
	return errors.New("new KSK signature not visible")
}
func (o *refusingObserver) AuthoritativeDNSKEYRRSIGBy(context.Context, string, model.Key) error {
	o.signatureChecks++
	return errors.New("new KSK signature not visible")
}
func (*refusingObserver) DelegationEvidence(context.Context, string, []string) error { return nil }

func TestParentRemoveRequiresNewKSKSignatureProof(t *testing.T) {
	st, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg := &fakeRegistrar{}
	obs := &refusingObserver{}
	c := New(testConfig(), fakePDNS{}, reg, obs, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	keys := []model.Key{{ID: 1, KeyType: "ksk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"}, {ID: 2, KeyType: "ksk", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"}, {ID: 3, KeyType: "zsk", Active: true, Published: true, DNSKEY: "256 3 13 BwgJ"}}
	w := model.Workflow{Zone: "example.test.", Kind: model.KindKSK, Phase: model.PhaseParentRemove, OldKeyID: 1, NewKeyID: 2, RegistrarCTID: "dnssec-test-1234"}
	if err := c.parentReplace(context.Background(), model.Zone{ID: "example.test.", Name: "example.test."}, keys, w); err == nil {
		t.Fatal("expected missing new-KSK signature proof to block parent removal")
	}
	if reg.updates != 0 {
		t.Fatal("registrar was mutated before signature proof")
	}
	if obs.signatureChecks != 1 {
		t.Fatalf("signature checks=%d", obs.signatureChecks)
	}
}

func TestArmEnrollmentBaselinesExistingZonesWithoutRegistrarWrite(t *testing.T) {
	zone := model.Zone{ID: "existing.test.", Name: "existing.test.", DNSSEC: true}
	p := &recordingPDNS{
		zones: []model.Zone{zone},
		keys: map[string][]model.Key{zone.ID: {
			{ID: 1, KeyType: "ksk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "257 3 13 AQID"},
			{ID: 2, KeyType: "zsk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "256 3 13 BAUG"},
		}},
	}
	reg := &fakeRegistrar{}
	c, st := newTestController(t, p, &evidenceObserver{})
	c.registrar = reg
	if err := c.ArmEnrollment(context.Background(), "arm-enrollment-test-0001"); err != nil {
		t.Fatal(err)
	}
	snapshot := st.Snapshot()
	if snapshot.EnrollmentArmedAt.IsZero() {
		t.Fatal("enrollment was not persistently armed")
	}
	w, ok := snapshot.Workflows[model.WorkflowKey(zone.Name, model.KindEnroll)]
	if !ok || w.Phase != model.PhaseIdle {
		t.Fatalf("existing zone was not baselined: %+v", w)
	}
	if reg.updates != 0 {
		t.Fatal("arming enrollment mutated the registrar")
	}
}

func TestArmedEnrollmentDiscoversOnlyNewCleanSplitZone(t *testing.T) {
	p := &recordingPDNS{keys: map[string][]model.Key{}}
	c, st := newTestController(t, p, &evidenceObserver{})
	c.cfg.Enrollment.Enabled = true
	if err := c.ArmEnrollment(context.Background(), "arm-enrollment-test-0002"); err != nil {
		t.Fatal(err)
	}
	zone := model.Zone{ID: "new.test.", Name: "new.test.", DNSSEC: true}
	p.zones = []model.Zone{zone}
	p.keys[zone.ID] = []model.Key{
		{ID: 11, KeyType: "ksk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "257 3 13 AQID"},
		{ID: 12, KeyType: "zsk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "256 3 13 BAUG"},
	}
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	w := st.Snapshot().Workflows[model.WorkflowKey(zone.Name, model.KindEnroll)]
	if w.Phase != model.PhaseEnrollDiscovered || w.NewKeyID != 11 || w.NewZSKID != 12 {
		t.Fatalf("new split zone was not persisted as an enrollment candidate: %+v", w)
	}
	if p.creates != 0 || p.setCalls != 0 || p.deletes != 0 {
		t.Fatalf("discovery mutated PowerDNS: create=%d set=%d delete=%d", p.creates, p.setCalls, p.deletes)
	}
}

func TestEnrollmentDoesNothingWithoutPersistedArmState(t *testing.T) {
	zone := model.Zone{ID: "new.test.", Name: "new.test.", DNSSEC: true}
	p := &recordingPDNS{zones: []model.Zone{zone}, keys: map[string][]model.Key{zone.ID: {
		{ID: 11, KeyType: "ksk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "257 3 13 AQID"},
		{ID: 12, KeyType: "zsk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "256 3 13 BAUG"},
	}}}
	c, st := newTestController(t, p, &evidenceObserver{})
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Snapshot().Workflows[model.WorkflowKey(zone.Name, model.KindEnroll)]; ok {
		t.Fatal("unarmed controller created an enrollment workflow")
	}
	if p.creates != 0 || p.setCalls != 0 || p.deletes != 0 {
		t.Fatal("unarmed enrollment mutated PowerDNS")
	}
}

func TestObserveModeOrphanSweepIsStrictlyReadOnly(t *testing.T) {
	p := &recordingPDNS{zones: nil, keys: map[string][]model.Key{}}
	c, st := newTestController(t, p, &evidenceObserver{})
	c.cfg.Mode = "observe"
	w := model.Workflow{Zone: "missing.test.", Kind: model.KindEnroll, Phase: model.PhaseEnrollDiscovered, DiscoveredAt: c.clock.Now().Add(-time.Hour)}
	if err := st.Update(func(s *model.State) error { s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	before := st.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)]
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := st.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)]
	if after != before {
		t.Fatalf("observe mode mutated orphan workflow: before=%+v after=%+v", before, after)
	}
}

func TestEnrollmentParentAddRequiresExactParentDelegation(t *testing.T) {
	st, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	reg := &fakeRegistrar{state: autodns.DomainDNSSECState{Enabled: false, Data: []model.DNSSECData{}}}
	obs := &evidenceObserver{delegationErr: errors.New("delegated to foreign nameservers")}
	c := New(testConfig(), fakePDNS{}, reg, obs, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	keys := []model.Key{
		{ID: 11, KeyType: "ksk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "257 3 13 AQID"},
		{ID: 12, KeyType: "zsk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "256 3 13 BAUG"},
	}
	_, _, fingerprint, err := validateEnrollmentInventory("new.test.", keys, 11, 12, "", []string{"ECDSAP256SHA256"})
	if err != nil {
		t.Fatal(err)
	}
	w := model.Workflow{Zone: "new.test.", ZoneID: "new.test.", Kind: model.KindEnroll, Phase: model.PhaseEnrollParentAdd, NewKeyID: 11, NewZSKID: 12, KeysetFingerprint: fingerprint, RegistrarCTID: "dnssec-enroll-test-0002"}
	if err := st.Update(func(s *model.State) error {
		s.EnrollmentArmedAt = time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
		s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.enrollParentAdd(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err == nil {
		t.Fatal("foreign parent delegation was accepted")
	}
	if reg.updates != 0 {
		t.Fatal("registrar was mutated without exact parent delegation")
	}
}

func TestEnrollmentConfigDisableBlocksCandidateBeforeRegistrarWrite(t *testing.T) {
	zone := model.Zone{ID: "new.test.", Name: "new.test.", DNSSEC: true}
	keys := []model.Key{
		{ID: 11, KeyType: "ksk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "257 3 13 AQID"},
		{ID: 12, KeyType: "zsk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "256 3 13 BAUG"},
	}
	_, _, fingerprint, err := validateEnrollmentInventory(zone.Name, keys, 11, 12, "", []string{"ECDSAP256SHA256"})
	if err != nil {
		t.Fatal(err)
	}
	p := &recordingPDNS{zones: []model.Zone{zone}, keys: map[string][]model.Key{zone.ID: keys}}
	c, st := newTestController(t, p, &evidenceObserver{})
	c.cfg.Enrollment.Enabled = false
	w := model.Workflow{Zone: zone.Name, ZoneID: zone.ID, Kind: model.KindEnroll, Phase: model.PhaseEnrollParentAdd, NewKeyID: 11, NewZSKID: 12, KeysetFingerprint: fingerprint}
	if err := st.Update(func(s *model.State) error {
		s.EnrollmentArmedAt = c.clock.Now().Add(-48 * time.Hour)
		s.Workflows[model.WorkflowKey(zone.Name, model.KindEnroll)] = w
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.Tick(context.Background()); err == nil {
		t.Fatal("disabled enrollment candidate did not fail closed")
	}
	if got := st.Snapshot().Workflows[model.WorkflowKey(zone.Name, model.KindEnroll)].Phase; got != model.PhaseBlocked {
		t.Fatalf("phase=%s", got)
	}
}

func TestEnrollmentRotationScopeRemovalBlocksCandidateBeforeRegistrarWrite(t *testing.T) {
	zone := model.Zone{ID: "new.test.", Name: "new.test.", DNSSEC: true}
	keys := []model.Key{
		{ID: 11, KeyType: "ksk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "257 3 13 AQID"},
		{ID: 12, KeyType: "zsk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "256 3 13 BAUG"},
	}
	_, _, fingerprint, err := validateEnrollmentInventory(zone.Name, keys, 11, 12, "", []string{"ECDSAP256SHA256"})
	if err != nil {
		t.Fatal(err)
	}
	p := &recordingPDNS{zones: []model.Zone{zone}, keys: map[string][]model.Key{zone.ID: keys}}
	c, st := newTestController(t, p, &evidenceObserver{})
	c.cfg.Rotation.ExcludeZones = []string{zone.Name}
	w := model.Workflow{Zone: zone.Name, ZoneID: zone.ID, Kind: model.KindEnroll, Phase: model.PhaseEnrollParentAdd, NewKeyID: 11, NewZSKID: 12, KeysetFingerprint: fingerprint}
	if err := st.Update(func(s *model.State) error {
		s.EnrollmentArmedAt = c.clock.Now().Add(-48 * time.Hour)
		s.Workflows[model.WorkflowKey(zone.Name, model.KindEnroll)] = w
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.Tick(context.Background()); err == nil {
		t.Fatal("out-of-scope enrollment candidate did not fail closed")
	}
	if got := st.Snapshot().Workflows[model.WorkflowKey(zone.Name, model.KindEnroll)].Phase; got != model.PhaseBlocked {
		t.Fatalf("phase=%s", got)
	}
}

func TestEnrollmentParentWriteRequiresPersistedArmState(t *testing.T) {
	st, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	reg := &fakeRegistrar{state: autodns.DomainDNSSECState{Enabled: false, Data: []model.DNSSECData{}}}
	c := New(testConfig(), fakePDNS{}, reg, &evidenceObserver{}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	keys := []model.Key{
		{ID: 11, KeyType: "ksk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "257 3 13 AQID"},
		{ID: 12, KeyType: "zsk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "256 3 13 BAUG"},
	}
	_, _, fingerprint, err := validateEnrollmentInventory("new.test.", keys, 11, 12, "", []string{"ECDSAP256SHA256"})
	if err != nil {
		t.Fatal(err)
	}
	w := model.Workflow{Zone: "new.test.", ZoneID: "new.test.", Kind: model.KindEnroll, Phase: model.PhaseEnrollParentAdd, NewKeyID: 11, NewZSKID: 12, KeysetFingerprint: fingerprint}
	if err := st.Update(func(s *model.State) error { s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := c.enrollParentAdd(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err == nil {
		t.Fatal("disarmed enrollment reached registrar write path")
	}
	if reg.updates != 0 {
		t.Fatal("registrar was mutated without persisted arm state")
	}
}

func TestEnrollmentParentAddWritesExactlyOnceAfterIntentPersistence(t *testing.T) {
	st, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	reg := &fakeRegistrar{state: autodns.DomainDNSSECState{Enabled: false, Data: []model.DNSSECData{}}}
	c := New(testConfig(), fakePDNS{}, reg, &evidenceObserver{}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.clock = fixedClock{time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)}
	keys := []model.Key{
		{ID: 11, KeyType: "ksk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "257 3 13 AQID"},
		{ID: 12, KeyType: "zsk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "256 3 13 BAUG"},
	}
	_, _, fingerprint, err := validateEnrollmentInventory("new.test.", keys, 11, 12, "", []string{"ECDSAP256SHA256"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := dnsprobe.DNSSECDataForKey("new.test.", keys[0])
	if err != nil {
		t.Fatal(err)
	}
	w := model.Workflow{Zone: "new.test.", ZoneID: "new.test.", Kind: model.KindEnroll, Phase: model.PhaseEnrollParentAdd, NewKeyID: 11, NewZSKID: 12, KeysetFingerprint: fingerprint, RegistrarCTID: "dnssec-enroll-test-0001", RegistrarPayloadHash: dnssecPayloadHash(data), ParentMode: parentModeInitial}
	if err := st.Update(func(s *model.State) error {
		s.EnrollmentArmedAt = c.clock.Now().Add(-time.Hour)
		s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.enrollParentAdd(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err != nil {
		t.Fatal(err)
	}
	got := st.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)]
	if got.RegistrarAttemptedAt.IsZero() || got.Phase != model.PhaseEnrollWaitParent {
		t.Fatalf("registrar intent or phase missing: %+v", got)
	}
	if reg.updates != 1 {
		t.Fatalf("registrar updates=%d want=1", reg.updates)
	}
	if err := c.enrollParentAdd(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, got); err != nil {
		t.Fatal(err)
	}
	if reg.updates != 1 {
		t.Fatalf("registrar write repeated: %d", reg.updates)
	}
}

func TestEnrollmentAmbiguousRegistrarWriteIsNeverResubmitted(t *testing.T) {
	st, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	reg := &fakeRegistrar{state: autodns.DomainDNSSECState{Enabled: false, Data: []model.DNSSECData{}}, updateErr: errors.New("timeout after send")}
	c := New(testConfig(), fakePDNS{}, reg, &evidenceObserver{}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.clock = fixedClock{time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)}
	keys := []model.Key{
		{ID: 11, KeyType: "ksk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "257 3 13 AQID"},
		{ID: 12, KeyType: "zsk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "256 3 13 BAUG"},
	}
	_, _, fingerprint, err := validateEnrollmentInventory("new.test.", keys, 11, 12, "", []string{"ECDSAP256SHA256"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := dnsprobe.DNSSECDataForKey("new.test.", keys[0])
	if err != nil {
		t.Fatal(err)
	}
	w := model.Workflow{Zone: "new.test.", ZoneID: "new.test.", Kind: model.KindEnroll, Phase: model.PhaseEnrollParentAdd, NewKeyID: 11, NewZSKID: 12, KeysetFingerprint: fingerprint, RegistrarCTID: "dnssec-enroll-test-0003", RegistrarPayloadHash: dnssecPayloadHash(data)}
	if err := st.Update(func(s *model.State) error {
		s.EnrollmentArmedAt = c.clock.Now().Add(-48 * time.Hour)
		s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.enrollParentAdd(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err == nil {
		t.Fatal("ambiguous registrar result was treated as success")
	}
	got := st.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)]
	if got.RegistrarAttemptedAt.IsZero() || reg.updates != 1 {
		t.Fatalf("write intent=%s updates=%d", got.RegistrarAttemptedAt, reg.updates)
	}
	reg.updateErr = nil
	reg.state = autodns.DomainDNSSECState{Enabled: true, Data: []model.DNSSECData{data}}
	if err := c.enrollParentAdd(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, got); err != nil {
		t.Fatal(err)
	}
	if reg.updates != 1 {
		t.Fatalf("ambiguous write was resubmitted: %d", reg.updates)
	}
	if phase := st.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)].Phase; phase != model.PhaseEnrollWaitParent {
		t.Fatalf("phase=%s", phase)
	}
}

func TestEnrollmentCompletionAtomicallyInitializesRotationsAndNotification(t *testing.T) {
	c, st := newTestController(t, &recordingPDNS{}, &evidenceObserver{})
	c.cfg.Notifications.LMTP.Enabled = true
	w := model.Workflow{Zone: "new.test.", ZoneID: "new.test.", Kind: model.KindEnroll, Phase: model.PhaseEnrollWaitParent, NewKeyID: 11, NewZSKID: 12, KeysetFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DiscoveredAt: c.clock.Now().Add(-96 * time.Hour)}
	if err := st.Update(func(s *model.State) error { s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := c.complete(w); err != nil {
		t.Fatal(err)
	}
	snapshot := st.Snapshot()
	enroll := snapshot.Workflows[model.WorkflowKey(w.Zone, model.KindEnroll)]
	if enroll.Phase != model.PhaseIdle || enroll.EnrollmentDisposition != "enrolled" {
		t.Fatalf("enrollment completion=%+v", enroll)
	}
	for _, kind := range []model.Kind{model.KindKSK, model.KindZSK} {
		role := snapshot.Workflows[model.WorkflowKey(w.Zone, kind)]
		if role.Phase != model.PhaseIdle || !role.LastCompletedAt.Equal(c.clock.Now()) {
			t.Fatalf("%s workflow=%+v", kind, role)
		}
	}
	if len(snapshot.Notifications) != 1 {
		t.Fatalf("notifications=%d", len(snapshot.Notifications))
	}
	for _, event := range snapshot.Notifications {
		if event.Event != "completed" || event.Kind != model.KindEnroll {
			t.Fatalf("notification=%+v", event)
		}
	}
}

func TestSplitParentActivationAcceptsProvenEmptyRegistrar(t *testing.T) {
	st, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg := &fakeRegistrar{}
	obs := &evidenceObserver{}
	c := New(testConfig(), fakePDNS{}, reg, obs, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.clock = fixedClock{time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)}
	keys := []model.Key{
		{ID: 1, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "ksk", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"},
		{ID: 3, KeyType: "zsk", Active: false, Published: true, DNSKEY: "256 3 13 BwgJ"},
	}
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhaseParentRemove, OldKeyID: 1, NewKeyID: 2, NewZSKID: 3, RegistrarCTID: "dnssec-split-activation-test", ParentMode: "initial"}
	if err := st.Update(func(s *model.State) error {
		s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.parentReplace(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err != nil {
		t.Fatalf("empty registrar material should be accepted for a proven split activation: %v", err)
	}
	if reg.updates != 1 {
		t.Fatalf("registrar updates=%d want=1", reg.updates)
	}
}

func TestSplitParentActivationRejectsUnpublishedKSKBeforeRegistrarWrite(t *testing.T) {
	st, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg := &fakeRegistrar{}
	c := New(testConfig(), fakePDNS{}, reg, &evidenceObserver{}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	keys := []model.Key{
		{ID: 1, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "ksk", Active: true, Published: false, DNSKEY: "257 3 13 BAUG"},
		{ID: 3, KeyType: "zsk", Active: false, Published: true, DNSKEY: "256 3 13 BwgJ"},
	}
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhaseParentRemove, OldKeyID: 1, NewKeyID: 2, NewZSKID: 3, RegistrarCTID: "dnssec-split-unpublished-test", ParentMode: parentModeInitial}
	if err := st.Update(func(s *model.State) error { s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := c.parentReplace(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err == nil {
		t.Fatal("unpublished KSK was accepted")
	}
	if reg.updates != 0 {
		t.Fatal("registrar was mutated for an unpublished KSK")
	}
}

func TestValidatePrepublishInventoryRejectsUnexpectedPublishedKey(t *testing.T) {
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, OldKeyID: 1, NewKeyID: 2, NewZSKID: 3}
	keys := []model.Key{
		{ID: 1, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "ksk", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"},
		{ID: 3, KeyType: "zsk", Active: false, Published: true, DNSKEY: "256 3 13 BwgJ"},
		{ID: 4, KeyType: "zsk", Active: false, Published: true, DNSKEY: "256 3 13 CgsM"},
	}
	if err := validatePrepublishInventory(w.Zone, keys, w); err == nil {
		t.Fatal("unexpected published key was accepted")
	}
}

func TestValidatePrepublishInventoryAcceptsPowerDNSTransitionalCSKLabelsByDNSKEYFlags(t *testing.T) {
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, OldKeyID: 1, NewKeyID: 2, NewZSKID: 3}
	keys := []model.Key{
		{ID: 1, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"},
		{ID: 3, KeyType: "csk", Active: false, Published: true, DNSKEY: "256 3 13 BwgJ"},
	}
	if err := validatePrepublishInventory(w.Zone, keys, w); err != nil {
		t.Fatalf("PowerDNS transitional labels rejected: %v", err)
	}
}

func TestValidatePrepublishInventoryRejectsTransitionalCSKWithWrongDNSKEYFlags(t *testing.T) {
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, OldKeyID: 1, NewKeyID: 2, NewZSKID: 3}
	keys := []model.Key{
		{ID: 1, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "csk", Active: true, Published: true, DNSKEY: "256 3 13 BAUG"},
		{ID: 3, KeyType: "csk", Active: false, Published: true, DNSKEY: "256 3 13 BwgJ"},
	}
	if err := validatePrepublishInventory(w.Zone, keys, w); err == nil {
		t.Fatal("transitional KSK with ZSK flags was accepted")
	}
}

func TestValidatePrepublishInventoryRejectsWrongDNSKEYProtocol(t *testing.T) {
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, OldKeyID: 1, NewKeyID: 2, NewZSKID: 3}
	keys := []model.Key{
		{ID: 1, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 2 13 BAUG"},
		{ID: 3, KeyType: "csk", Active: false, Published: true, DNSKEY: "256 3 13 BwgJ"},
	}
	if err := validatePrepublishInventory(w.Zone, keys, w); err == nil {
		t.Fatal("transitional KSK with DNSKEY protocol other than 3 was accepted")
	}
}

func TestValidatePrepublishInventoryDoesNotAcceptTransitionalCSKOutsideSplit(t *testing.T) {
	w := model.Workflow{Zone: "example.test.", Kind: model.KindKSK, OldKeyID: 1, NewKeyID: 2}
	keys := []model.Key{
		{ID: 1, KeyType: "ksk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"},
		{ID: 3, KeyType: "zsk", Active: true, Published: true, DNSKEY: "256 3 13 BwgJ"},
	}
	if err := validatePrepublishInventory(w.Zone, keys, w); err == nil {
		t.Fatal("transitional CSK label was accepted for an ordinary KSK rotation")
	}
}

func TestValidatePrepublishInventoryRejectsReusedKeyIDs(t *testing.T) {
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, OldKeyID: 1, NewKeyID: 1, NewZSKID: 3}
	keys := []model.Key{
		{ID: 1, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 3, KeyType: "csk", Active: false, Published: true, DNSKEY: "256 3 13 BwgJ"},
	}
	if err := validatePrepublishInventory(w.Zone, keys, w); err == nil {
		t.Fatal("same PowerDNS key ID was accepted as old and new KSK")
	}
}

func TestSplitPrepublishClassifiesInitialBeforeCreatingKeys(t *testing.T) {
	p := &recordingPDNS{}
	c, s := newTestController(t, p, &evidenceObserver{})
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhasePrepublish, OldKeyID: 1}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	keys := []model.Key{{ID: 1, KeyType: "csk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "257 3 13 AQID"}}
	if err := c.prepublish(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err != nil {
		t.Fatal(err)
	}
	got := s.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)]
	if got.ParentMode != parentModeInitial || p.createdActive != nil {
		t.Fatalf("workflow=%+v created=%v", got, p.createdActive)
	}
}

func TestSplitPrepublishRejectsEnabledEmptyRegistrar(t *testing.T) {
	p := &recordingPDNS{}
	s, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg := &fakeRegistrar{state: autodns.DomainDNSSECState{Enabled: true}}
	c := New(testConfig(), p, reg, &evidenceObserver{}, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhasePrepublish, OldKeyID: 1}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	keys := []model.Key{{ID: 1, KeyType: "csk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "257 3 13 AQID"}}
	if err := c.prepublish(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err == nil {
		t.Fatal("expected enabled-empty registrar state to block")
	}
	if p.createdActive != nil {
		t.Fatal("created a key before registrar-state classification")
	}
}

func testConfig() config.Config {
	return config.Config{Mode: "enforce", Controller: config.Controller{PropagationMargin: 2 * time.Hour}, Rotation: config.Rotation{Algorithm: "ECDSAP256SHA256", MinimumDNSKEYWait: 24 * time.Hour, MinimumParentWait: 48 * time.Hour}, Enrollment: config.Enrollment{Enabled: true, Scope: "all_selected", DiscoveryGrace: 24 * time.Hour, MaxPending: 10, MaxNewPerDay: 5, AllowedAlgorithms: []string{"ECDSAP256SHA256"}}, DNS: config.DNS{ExpectedNameservers: []string{"ns1.example.test", "ns2.example.test"}}}
}

type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }

type evidenceObserver struct {
	dnskeyTTL, parentTTL time.Duration
	delegationErr        error
}

func (o *evidenceObserver) DNSKEYEvidence(context.Context, string, ...model.Key) (time.Duration, error) {
	return o.dnskeyTTL, nil
}
func (o *evidenceObserver) AuthoritativeDNSKEYEvidence(context.Context, string, ...model.Key) (time.Duration, error) {
	return o.dnskeyTTL, nil
}
func (o *evidenceObserver) NoDSEvidence(context.Context, string) error            { return nil }
func (o *evidenceObserver) DSEvidence(context.Context, string, []model.Key) error { return nil }
func (o *evidenceObserver) AuthoritativeDSEvidence(context.Context, string, []model.Key) (time.Duration, error) {
	return o.parentTTL, nil
}
func (o *evidenceObserver) RRSIGBy(context.Context, string, model.Key) error { return nil }
func (o *evidenceObserver) AuthoritativeRRSIGBy(context.Context, string, model.Key) error {
	return nil
}
func (o *evidenceObserver) DNSKEYRRSIGBy(context.Context, string, model.Key) error { return nil }
func (o *evidenceObserver) AuthoritativeDNSKEYRRSIGBy(context.Context, string, model.Key) error {
	return nil
}
func (o *evidenceObserver) DelegationEvidence(context.Context, string, []string) error {
	return o.delegationErr
}

type recordingNotifier struct {
	events []model.Notification
	err    error
}

func (n *recordingNotifier) Send(_ context.Context, event model.Notification) error {
	n.events = append(n.events, event)
	return n.err
}

type recordingPDNS struct {
	zones         []model.Zone
	keys          map[string][]model.Key
	createdActive *bool
	deletes       int
	zoneTTL       uint32
	setCalls      int
	creates       int
	createErr     error
	createResult  model.Key
}

type failingListPDNS struct{ recordingPDNS }

func (f *failingListPDNS) ListZones(context.Context) ([]model.Zone, error) {
	return nil, errors.New("powerdns unavailable")
}

func (p *recordingPDNS) ListZones(context.Context) ([]model.Zone, error) { return p.zones, nil }
func (p *recordingPDNS) GetZone(context.Context, string) (model.Zone, error) {
	ttl := p.zoneTTL
	if ttl == 0 {
		ttl = 86400
	}
	return model.Zone{RRsets: []model.RRSet{{TTL: ttl}}}, nil
}
func (p *recordingPDNS) ListKeys(_ context.Context, id string) ([]model.Key, error) {
	return p.keys[id], nil
}
func (p *recordingPDNS) CreateKey(_ context.Context, _ string, typ, algo string, active bool) (model.Key, error) {
	p.creates++
	p.createdActive = &active
	if p.createErr != nil {
		return model.Key{}, p.createErr
	}
	if p.createResult.ID != 0 {
		return p.createResult, nil
	}
	return model.Key{ID: 2, KeyType: typ, Algorithm: algo, Active: active, Published: true, DNSKEY: "257 3 13 BAUG"}, nil
}

func TestSplitAdoptOrCreateAdoptsPowerDNSTransitionalRoleAfterAmbiguousPOST(t *testing.T) {
	for _, tc := range []struct {
		name   string
		typ    string
		active bool
		key    model.Key
	}{
		{name: "ksk", typ: "ksk", active: true, key: model.Key{ID: 2, KeyType: "csk", Algorithm: "ECDSAP256SHA256", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"}},
		{name: "zsk", typ: "zsk", active: false, key: model.Key{ID: 3, KeyType: "csk", Algorithm: "ECDSAP256SHA256", Active: false, Published: true, DNSKEY: "256 3 13 BwgJ"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &recordingPDNS{}
			c, _ := newTestController(t, p, &evidenceObserver{})
			w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhasePrepublish, OldKeyID: 1}
			got, err := c.adoptOrCreate(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, []model.Key{tc.key}, w, tc.typ, "ECDSAP256SHA256", 1, tc.active, true, tc.typ == "zsk")
			if err != nil {
				t.Fatal(err)
			}
			if got.ID != tc.key.ID || p.creates != 0 {
				t.Fatalf("key=%+v creates=%d", got, p.creates)
			}
		})
	}
}

func TestSplitAdoptOrCreateRejectsAmbiguousTransitionalCandidates(t *testing.T) {
	p := &recordingPDNS{}
	c, _ := newTestController(t, p, &evidenceObserver{})
	keys := []model.Key{
		{ID: 2, KeyType: "csk", Algorithm: "ECDSAP256SHA256", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"},
		{ID: 4, KeyType: "csk", Algorithm: "ECDSAP256SHA256", Active: true, Published: true, DNSKEY: "257 3 13 CAkK"},
	}
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhasePrepublish, OldKeyID: 1}
	if _, err := c.adoptOrCreate(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w, "ksk", "ECDSAP256SHA256", 1, true, true, false); err == nil {
		t.Fatal("ambiguous transitional candidates were accepted")
	}
	if p.creates != 0 {
		t.Fatal("created a key despite ambiguous candidates")
	}
}

func TestSplitCreateAttemptPreventsDuplicateAfterAmbiguousPOSTAndEmptyReadBack(t *testing.T) {
	p := &recordingPDNS{createErr: errors.New("response lost after commit")}
	c, st := newTestController(t, p, &evidenceObserver{})
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhasePrepublish, OldKeyID: 1, ParentMode: parentModeInitial}
	if err := st.Update(func(s *model.State) error { s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	oldOnly := []model.Key{{ID: 1, KeyType: "csk", Algorithm: "ECDSAP256SHA256", Active: true, Published: true, DNSKEY: "257 3 13 AQID"}}
	zone := model.Zone{ID: w.Zone, Name: w.Zone}
	if err := c.prepublish(context.Background(), zone, oldOnly, w); err == nil {
		t.Fatal("ambiguous create unexpectedly succeeded")
	}
	afterAttempt := st.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)]
	if afterAttempt.NewKeyCreateAttemptedAt.IsZero() || p.creates != 1 {
		t.Fatalf("workflow=%+v creates=%d", afterAttempt, p.creates)
	}
	if err := c.prepublish(context.Background(), zone, oldOnly, afterAttempt); err == nil {
		t.Fatal("empty read-back after an attempted create unexpectedly succeeded")
	}
	if p.creates != 1 {
		t.Fatalf("duplicate create issued: %d calls", p.creates)
	}
}

func TestSplitCreateResponseIsValidatedBeforePersistingID(t *testing.T) {
	p := &recordingPDNS{createResult: model.Key{ID: 2, KeyType: "csk", Algorithm: "ECDSAP256SHA256", Active: true, Published: true, DNSKEY: "256 3 13 BAUG"}}
	c, st := newTestController(t, p, &evidenceObserver{})
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhasePrepublish, OldKeyID: 1, ParentMode: parentModeInitial}
	if err := st.Update(func(s *model.State) error { s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	oldOnly := []model.Key{{ID: 1, KeyType: "csk", Algorithm: "ECDSAP256SHA256", Active: true, Published: true, DNSKEY: "257 3 13 AQID"}}
	if err := c.prepublish(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, oldOnly, w); err == nil {
		t.Fatal("created KSK response with ZSK flags was accepted")
	}
	if got := st.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)]; got.NewKeyID != 0 || got.NewKeyCreateAttemptedAt.IsZero() {
		t.Fatalf("workflow=%+v", got)
	}
}

func TestSplitCreateResponseCannotReuseOldKeyIDOrReachRegistrar(t *testing.T) {
	p := &recordingPDNS{createResult: model.Key{ID: 1, KeyType: "csk", Algorithm: "ECDSAP256SHA256", Active: true, Published: true, DNSKEY: "257 3 13 AQID"}}
	st, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	reg := &fakeRegistrar{}
	c := New(testConfig(), p, reg, &evidenceObserver{}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhasePrepublish, OldKeyID: 1, ParentMode: parentModeInitial}
	if err := st.Update(func(s *model.State) error { s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	oldOnly := []model.Key{{ID: 1, KeyType: "csk", Algorithm: "ECDSAP256SHA256", Active: true, Published: true, DNSKEY: "257 3 13 AQID"}}
	if err := c.prepublish(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, oldOnly, w); err == nil {
		t.Fatal("created replacement reused the old key ID")
	}
	if reg.updates != 0 || st.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)].NewKeyID != 0 {
		t.Fatal("duplicate ID advanced workflow or reached registrar")
	}
}

func TestSplitCreateResponseRejectsAlgorithmLabelDNSKEYMismatch(t *testing.T) {
	p := &recordingPDNS{createResult: model.Key{ID: 2, KeyType: "csk", Algorithm: "ECDSAP256SHA256", Active: true, Published: true, DNSKEY: "257 3 8 BAUG"}}
	c, st := newTestController(t, p, &evidenceObserver{})
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhasePrepublish, OldKeyID: 1, ParentMode: parentModeInitial}
	if err := st.Update(func(s *model.State) error { s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	oldOnly := []model.Key{{ID: 1, KeyType: "csk", Algorithm: "ECDSAP256SHA256", Active: true, Published: true, DNSKEY: "257 3 13 AQID"}}
	if err := c.prepublish(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, oldOnly, w); err == nil {
		t.Fatal("PowerDNS algorithm label/DNSKEY mismatch was accepted")
	}
}

func TestSplitZSKCreateAttemptPreventsDuplicateAfterAmbiguousPOSTAndEmptyReadBack(t *testing.T) {
	p := &recordingPDNS{createErr: errors.New("response lost after commit")}
	c, st := newTestController(t, p, &evidenceObserver{})
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhasePrepublish, OldKeyID: 1, NewKeyID: 2, ParentMode: parentModeInitial}
	if err := st.Update(func(s *model.State) error { s.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	withoutZSK := []model.Key{
		{ID: 1, KeyType: "csk", Algorithm: "ECDSAP256SHA256", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "csk", Algorithm: "ECDSAP256SHA256", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"},
	}
	zone := model.Zone{ID: w.Zone, Name: w.Zone}
	if err := c.prepublish(context.Background(), zone, withoutZSK, w); err == nil {
		t.Fatal("ambiguous ZSK create unexpectedly succeeded")
	}
	afterAttempt := st.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)]
	if afterAttempt.NewZSKCreateAttemptedAt.IsZero() || p.creates != 1 {
		t.Fatalf("workflow=%+v creates=%d", afterAttempt, p.creates)
	}
	if err := c.prepublish(context.Background(), zone, withoutZSK, afterAttempt); err == nil {
		t.Fatal("empty ZSK read-back after an attempted create unexpectedly succeeded")
	}
	if p.creates != 1 {
		t.Fatalf("duplicate ZSK create issued: %d calls", p.creates)
	}
}
func (p *recordingPDNS) SetKey(context.Context, string, model.Key, bool, bool) error {
	p.setCalls++
	return nil
}
func (p *recordingPDNS) DeleteKey(context.Context, string, int) error { p.deletes++; return nil }

func newTestController(t *testing.T, p pdns.API, o dnsprobe.Observer) (*Controller, *state.Store) {
	t.Helper()
	s, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	c := New(testConfig(), p, &fakeRegistrar{}, o, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.clock = fixedClock{time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)}
	return c, s
}

func TestDeactivateOldPersistsRaisedTTLBeforeMutation(t *testing.T) {
	p := &recordingPDNS{zoneTTL: 72 * 3600}
	o := &evidenceObserver{}
	c, s := newTestController(t, p, o)
	w := model.Workflow{Zone: "example.test.", Kind: model.KindZSK, Phase: model.PhaseDeactivateOld, OldKeyID: 1, NewKeyID: 2, ZoneTTL: 3600}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	keys := []model.Key{{ID: 1, KeyType: "zsk", Active: true, Published: true, DNSKEY: "256 3 13 AQID"}, {ID: 2, KeyType: "zsk", Active: true, Published: true, DNSKEY: "256 3 13 BAUG"}}
	if err := c.deactivateOld(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err != nil {
		t.Fatal(err)
	}
	if p.setCalls != 0 {
		t.Fatal("old key was deactivated before raised TTL was persisted")
	}
	got := s.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)]
	if got.ZoneTTL != int64(72*time.Hour/time.Second) || got.Phase != model.PhaseDeactivateOld {
		t.Fatalf("workflow=%+v", got)
	}
	if !got.NextActionAt.Equal(c.clock.Now().Add(74 * time.Hour)) {
		t.Fatalf("next action=%s want=%s", got.NextActionAt, c.clock.Now().Add(74*time.Hour))
	}
	if err := c.advance(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, got); err != nil {
		t.Fatal(err)
	}
	if p.setCalls != 0 {
		t.Fatal("old key was deactivated before the raised TTL overlap elapsed")
	}
}

func TestDeactivateOldRejectsUnpublishedReplacement(t *testing.T) {
	p := &recordingPDNS{}
	c, s := newTestController(t, p, &evidenceObserver{})
	w := model.Workflow{Zone: "example.test.", Kind: model.KindZSK, Phase: model.PhaseDeactivateOld, OldKeyID: 1, NewKeyID: 2, ZoneTTL: 86400}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	keys := []model.Key{{ID: 1, KeyType: "zsk", Active: true, Published: true}, {ID: 2, KeyType: "zsk", Active: true, Published: false}}
	if err := c.deactivateOld(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err == nil {
		t.Fatal("unpublished replacement accepted")
	}
	if p.setCalls != 0 {
		t.Fatal("old key mutated despite unpublished replacement")
	}
}

func TestSplitActivateNewRejectsUnpublishedZSKWithoutMutation(t *testing.T) {
	p := &recordingPDNS{}
	c, s := newTestController(t, p, &evidenceObserver{})
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhaseActivateNew, OldKeyID: 1, NewKeyID: 2, NewZSKID: 3, ParentMode: parentModeInitial}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	keys := []model.Key{
		{ID: 1, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"},
		{ID: 3, KeyType: "csk", Active: false, Published: false, DNSKEY: "256 3 13 BwgJ"},
	}
	if err := c.activateNew(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err == nil {
		t.Fatal("unpublished split ZSK was activated")
	}
	if p.setCalls != 0 {
		t.Fatal("PowerDNS was mutated before closed pre-activation inventory validation")
	}
}

func TestSplitActivateNewReconcilesExactCommittedPostStateWithoutSecondMutation(t *testing.T) {
	p := &recordingPDNS{}
	c, s := newTestController(t, p, &evidenceObserver{})
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhaseActivateNew, OldKeyID: 1, NewKeyID: 2, NewZSKID: 3, ParentMode: parentModeInitial}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	keys := []model.Key{
		{ID: 1, KeyType: "ksk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "ksk", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"},
		{ID: 3, KeyType: "zsk", Active: true, Published: true, DNSKEY: "256 3 13 BwgJ"},
	}
	if err := c.activateNew(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err != nil {
		t.Fatal(err)
	}
	if p.setCalls != 0 {
		t.Fatal("already-committed ZSK activation was written a second time")
	}
	if got := s.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)].Phase; got != model.PhaseWaitNewSignature {
		t.Fatalf("phase=%s", got)
	}
}

func TestSplitDeactivateOldRejectsExtraPublishedKeyWithoutMutation(t *testing.T) {
	p := &recordingPDNS{}
	c, s := newTestController(t, p, &evidenceObserver{})
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhaseDeactivateOld, OldKeyID: 1, NewKeyID: 2, NewZSKID: 3, ParentMode: parentModeInitial, ZoneTTL: 86400}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	keys := []model.Key{
		{ID: 1, KeyType: "ksk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "ksk", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"},
		{ID: 3, KeyType: "zsk", Active: true, Published: true, DNSKEY: "256 3 13 BwgJ"},
		{ID: 4, KeyType: "zsk", Active: false, Published: true, DNSKEY: "256 3 13 CgsM"},
	}
	if err := c.deactivateOld(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err == nil {
		t.Fatal("extra published key was accepted before CSK deactivation")
	}
	if p.setCalls != 0 {
		t.Fatal("PowerDNS was mutated despite non-closed active split inventory")
	}
}

func TestSplitDeactivateOldReconcilesExactCommittedPostStateWithoutSecondMutation(t *testing.T) {
	p := &recordingPDNS{}
	c, s := newTestController(t, p, &evidenceObserver{})
	w := model.Workflow{Zone: "example.test.", Kind: model.KindSplit, Phase: model.PhaseDeactivateOld, OldKeyID: 1, NewKeyID: 2, NewZSKID: 3, ParentMode: parentModeInitial, ZoneTTL: 86400}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	keys := []model.Key{
		{ID: 1, KeyType: "ksk", Active: false, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "ksk", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"},
		{ID: 3, KeyType: "zsk", Active: true, Published: true, DNSKEY: "256 3 13 BwgJ"},
	}
	if err := c.deactivateOld(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err != nil {
		t.Fatal(err)
	}
	if p.setCalls != 0 {
		t.Fatal("already-committed CSK deactivation was written a second time")
	}
	if got := s.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)].Phase; got != model.PhaseWaitRetire {
		t.Fatalf("phase=%s", got)
	}
}

func TestCompletePersistsAndDeliversNotificationOnce(t *testing.T) {
	c, s := newTestController(t, &recordingPDNS{}, &evidenceObserver{})
	c.cfg.Notifications.LMTP.Enabled = true
	notifier := &recordingNotifier{}
	c.SetNotifier(notifier)
	w := model.Workflow{Zone: "example.test.", Kind: model.KindZSK, Phase: model.PhaseDeleteOld, OldKeyID: 1, NewKeyID: 2}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := c.complete(w); err != nil {
		t.Fatal(err)
	}
	if len(s.Snapshot().Notifications) != 1 {
		t.Fatal("completion notification was not persisted")
	}
	if err := c.deliverNotifications(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.deliverNotifications(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(notifier.events) != 1 || notifier.events[0].Zone != w.Zone {
		t.Fatalf("events=%+v", notifier.events)
	}
}

func TestDisabledNotificationsAreNotEnqueued(t *testing.T) {
	c, s := newTestController(t, &recordingPDNS{}, &evidenceObserver{})
	w := model.Workflow{Zone: "example.test.", Kind: model.KindZSK, Phase: model.PhaseDeleteOld}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := c.complete(w); err != nil {
		t.Fatal(err)
	}
	if len(s.Snapshot().Notifications) != 0 {
		t.Fatal("disabled notification was enqueued")
	}
}

func TestOutboxDeliversDuringPowerDNSFailure(t *testing.T) {
	c, s := newTestController(t, &failingListPDNS{}, &evidenceObserver{})
	c.cfg.Notifications.LMTP.Enabled = true
	notifier := &recordingNotifier{}
	c.SetNotifier(notifier)
	event := model.Notification{ID: "event-pdns-down", Zone: "example.test.", Kind: model.KindZSK, CompletedAt: c.clock.Now(), NextAttemptAt: c.clock.Now()}
	if err := s.Update(func(st *model.State) error { st.Notifications[event.ID] = event; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := c.Tick(context.Background()); err == nil {
		t.Fatal("expected PowerDNS failure")
	}
	if len(notifier.events) != 1 || s.Snapshot().Notifications[event.ID].DeliveredAt.IsZero() {
		t.Fatal("outbox did not deliver independently of PowerDNS")
	}
}

func TestOutboxFailurePersistsBackoff(t *testing.T) {
	c, s := newTestController(t, &recordingPDNS{}, &evidenceObserver{})
	c.cfg.Notifications.LMTP.Enabled = true
	notifier := &recordingNotifier{err: errors.New("LMTP unavailable")}
	c.SetNotifier(notifier)
	event := model.Notification{ID: "event-backoff", Zone: "example.test.", Kind: model.KindZSK, CompletedAt: c.clock.Now(), NextAttemptAt: c.clock.Now()}
	if err := s.Update(func(st *model.State) error { st.Notifications[event.ID] = event; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := c.deliverNotifications(context.Background()); err == nil {
		t.Fatal("expected LMTP error")
	}
	got := s.Snapshot().Notifications[event.ID]
	if got.Attempts != 1 || !got.NextAttemptAt.Equal(c.clock.Now().Add(2*time.Minute)) || got.LastError == "" {
		t.Fatalf("event=%+v", got)
	}
	if err := c.deliverNotifications(context.Background()); err != nil {
		t.Fatal("backoff should suppress immediate retry")
	}
	if len(notifier.events) != 1 {
		t.Fatal("event retried before backoff expired")
	}
}

func TestKSKPrepublishCreatesActiveCandidate(t *testing.T) {
	p := &recordingPDNS{}
	o := &evidenceObserver{}
	c, s := newTestController(t, p, o)
	w := model.Workflow{Zone: "example.test.", Kind: model.KindKSK, Phase: model.PhasePrepublish, OldKeyID: 1}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	keys := []model.Key{{ID: 1, KeyType: "ksk", Active: true, Published: true, Algorithm: "ECDSAP256SHA256", DNSKEY: "257 3 13 AQID"}}
	if err := c.prepublish(context.Background(), model.Zone{ID: w.Zone, Name: w.Zone}, keys, w); err != nil {
		t.Fatal(err)
	}
	if p.createdActive == nil || !*p.createdActive {
		t.Fatal("KSK candidate was not created active for double-KSK")
	}
}

func TestWaitPublishPersistsAuthoritativeTTL(t *testing.T) {
	p := &recordingPDNS{}
	o := &evidenceObserver{dnskeyTTL: 48 * time.Hour}
	c, s := newTestController(t, p, o)
	w := model.Workflow{Zone: "example.test.", Kind: model.KindZSK, Phase: model.PhaseWaitPublish, OldKeyID: 1, NewKeyID: 2}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	keys := []model.Key{{ID: 1, KeyType: "zsk", Active: true, Published: true, DNSKEY: "256 3 13 AQID"}, {ID: 2, KeyType: "zsk", Published: true, DNSKEY: "256 3 13 BAUG"}, {ID: 3, KeyType: "ksk", Active: true, Published: true, DNSKEY: "257 3 13 BwgJ"}}
	if err := c.waitPublish(context.Background(), model.Zone{Name: w.Zone}, keys, w); err != nil {
		t.Fatal(err)
	}
	got := s.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)]
	if got.DNSKEYTTL != int64((48*time.Hour)/time.Second) {
		t.Fatalf("ttl=%d", got.DNSKEYTTL)
	}
	want := c.clock.Now().Add(50 * time.Hour)
	if !got.NextActionAt.Equal(want) {
		t.Fatalf("next=%s want=%s", got.NextActionAt, want)
	}
}

func TestParentWaitPersistsAuthoritativeDSTTL(t *testing.T) {
	p := &recordingPDNS{}
	o := &evidenceObserver{parentTTL: 72 * time.Hour}
	c, s := newTestController(t, p, o)
	w := model.Workflow{Zone: "example.test.", Kind: model.KindKSK, Phase: model.PhaseWaitParentRemove, OldKeyID: 1, NewKeyID: 2}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	keys := []model.Key{{ID: 1, KeyType: "ksk", DNSKEY: "257 3 13 AQID"}, {ID: 2, KeyType: "ksk", Active: true, DNSKEY: "257 3 13 BAUG"}}
	if err := c.waitParentReplace(context.Background(), model.Zone{Name: w.Zone}, keys, w); err != nil {
		t.Fatal(err)
	}
	got := s.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)]
	if got.ParentDSTTL != int64((72*time.Hour)/time.Second) {
		t.Fatalf("ttl=%d", got.ParentDSTTL)
	}
	if !got.NextActionAt.Equal(c.clock.Now().Add(74 * time.Hour)) {
		t.Fatalf("next=%s", got.NextActionAt)
	}
}

func TestTriggerBatchIsAtomicAndReplaySafe(t *testing.T) {
	active := []model.Key{{ID: 1, KeyType: "ksk", Active: true}, {ID: 2, KeyType: "zsk", Active: true}}
	p := &recordingPDNS{zones: []model.Zone{{ID: "a.test.", Name: "a.test.", DNSSEC: true}, {ID: "b.test.", Name: "b.test.", DNSSEC: true}}, keys: map[string][]model.Key{"a.test.": active, "b.test.": active}}
	c, s := newTestController(t, p, &evidenceObserver{})
	idem := "batch-idempotency-0001"
	if err := c.Trigger(context.Background(), model.KindZSK, []string{"a.test", "missing.test"}, idem); err == nil {
		t.Fatal("expected invalid batch")
	}
	if len(s.Snapshot().Workflows) != 0 {
		t.Fatal("partial workflow persisted")
	}
	if err := c.Trigger(context.Background(), model.KindZSK, []string{"b.test", "a.test"}, idem); err != nil {
		t.Fatal(err)
	}
	before := s.Snapshot()
	if err := c.Trigger(context.Background(), model.KindZSK, []string{"a.test", "b.test"}, idem); err != nil {
		t.Fatalf("idempotent replay failed: %v", err)
	}
	after := s.Snapshot()
	if len(after.Workflows) != len(before.Workflows) {
		t.Fatal("replay changed workflow count")
	}
}

func TestTriggerRejectsZoneOutsideConfiguredScope(t *testing.T) {
	active := []model.Key{{ID: 1, KeyType: "ksk", Active: true}, {ID: 2, KeyType: "zsk", Active: true}}
	p := &recordingPDNS{zones: []model.Zone{{ID: "excluded.test.", Name: "excluded.test.", DNSSEC: true}}, keys: map[string][]model.Key{"excluded.test.": active}}
	c, s := newTestController(t, p, &evidenceObserver{})
	c.cfg.Rotation.ExcludeZones = []string{"excluded.test"}
	if err := c.Trigger(context.Background(), model.KindZSK, []string{"excluded.test"}, "trigger-excluded-zone-0001"); err == nil {
		t.Fatal("manual trigger accepted a zone outside configured scope")
	}
	if len(s.Snapshot().Workflows) != 0 {
		t.Fatal("out-of-scope trigger persisted a workflow")
	}
}

func TestResumeSplitWaitPublishRevalidatesAndPersistsAtomically(t *testing.T) {
	zone := "example.test."
	keys := []model.Key{
		{ID: 1, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"},
		{ID: 3, KeyType: "csk", Active: false, Published: true, DNSKEY: "256 3 13 BwgJ"},
	}
	p := &recordingPDNS{
		zones: []model.Zone{{ID: zone, Name: zone, DNSSEC: true}},
		keys:  map[string][]model.Key{zone: keys},
	}
	st, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	reg := &fakeRegistrar{state: autodns.DomainDNSSECState{Enabled: false}}
	c := New(testConfig(), p, reg, &evidenceObserver{}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.clock = fixedClock{time.Date(2026, 7, 17, 13, 0, 0, 0, time.UTC)}
	w := model.Workflow{Zone: zone, Kind: model.KindSplit, Phase: model.PhaseBlocked, OldKeyID: 1, NewKeyID: 2, NewZSKID: 3, ParentMode: parentModeInitial, LastError: "recorded new ksk has unexpected active/published state", DNSKEYTTL: 86400}
	if err := st.Update(func(s *model.State) error {
		s.Workflows[model.WorkflowKey(zone, model.KindSplit)] = w
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	idem := "resume-split-wait-publish-0001"
	if err := c.Resume(context.Background(), model.KindSplit, []string{"example.test"}, model.PhaseWaitPublish, idem); err != nil {
		t.Fatal(err)
	}
	got := st.Snapshot().Workflows[model.WorkflowKey(zone, model.KindSplit)]
	if got.Phase != model.PhaseWaitPublish || got.LastError != "" || got.DNSKEYTTL != 0 || !got.NextActionAt.Equal(c.clock.Now()) {
		t.Fatalf("workflow=%+v", got)
	}
	if reg.updates != 0 {
		t.Fatal("resume wrote to registrar")
	}
	if p.creates != 0 || p.setCalls != 0 || p.deletes != 0 {
		t.Fatalf("resume mutated PowerDNS: creates=%d sets=%d deletes=%d", p.creates, p.setCalls, p.deletes)
	}
	if err := c.Resume(context.Background(), model.KindSplit, []string{zone}, model.PhaseWaitPublish, idem); err != nil {
		t.Fatalf("idempotent resume replay failed: %v", err)
	}
}

func TestResumeSplitWaitPublishRejectsWrongDNSKEYFlagsWithoutStateChange(t *testing.T) {
	zone := "example.test."
	keys := []model.Key{
		{ID: 1, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
		{ID: 2, KeyType: "csk", Active: true, Published: true, DNSKEY: "256 3 13 BAUG"},
		{ID: 3, KeyType: "csk", Active: false, Published: true, DNSKEY: "256 3 13 BwgJ"},
	}
	p := &recordingPDNS{zones: []model.Zone{{ID: zone, Name: zone, DNSSEC: true}}, keys: map[string][]model.Key{zone: keys}}
	c, st := newTestController(t, p, &evidenceObserver{})
	w := model.Workflow{Zone: zone, Kind: model.KindSplit, Phase: model.PhaseBlocked, OldKeyID: 1, NewKeyID: 2, NewZSKID: 3, ParentMode: parentModeInitial}
	if err := st.Update(func(s *model.State) error { s.Workflows[model.WorkflowKey(zone, model.KindSplit)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(context.Background(), model.KindSplit, []string{zone}, model.PhaseWaitPublish, "resume-split-wrong-flags-0001"); err == nil {
		t.Fatal("resume accepted wrong KSK flags")
	}
	if got := st.Snapshot().Workflows[model.WorkflowKey(zone, model.KindSplit)]; got.Phase != model.PhaseBlocked {
		t.Fatalf("phase=%s", got.Phase)
	}
}

func TestResumeRejectsZoneOutsideConfiguredScope(t *testing.T) {
	zone := "example.test."
	p := &recordingPDNS{zones: []model.Zone{{ID: zone, Name: zone, DNSSEC: true}}}
	c, st := newTestController(t, p, &evidenceObserver{})
	c.cfg.Rotation.ExcludeZones = []string{zone}
	w := model.Workflow{Zone: zone, Kind: model.KindSplit, Phase: model.PhaseBlocked, OldKeyID: 1, NewKeyID: 2, NewZSKID: 3, ParentMode: parentModeInitial}
	if err := st.Update(func(s *model.State) error { s.Workflows[model.WorkflowKey(zone, model.KindSplit)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(context.Background(), model.KindSplit, []string{zone}, model.PhaseWaitPublish, "resume-excluded-zone-0001"); err == nil {
		t.Fatal("resume accepted a zone outside configured scope")
	}
	if got := st.Snapshot().Workflows[model.WorkflowKey(zone, model.KindSplit)].Phase; got != model.PhaseBlocked {
		t.Fatalf("phase=%s", got)
	}
}

func TestDeleteAmbiguousSuccessReconcilesMissingOldKey(t *testing.T) {
	p := &recordingPDNS{}
	o := &evidenceObserver{}
	c, s := newTestController(t, p, o)
	w := model.Workflow{Zone: "example.test.", Kind: model.KindKSK, Phase: model.PhaseDeleteOld, OldKeyID: 1, NewKeyID: 2}
	if err := s.Update(func(st *model.State) error { st.Workflows[model.WorkflowKey(w.Zone, w.Kind)] = w; return nil }); err != nil {
		t.Fatal(err)
	}
	keys := []model.Key{{ID: 2, KeyType: "ksk", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"}}
	if err := c.deleteOld(context.Background(), model.Zone{Name: w.Zone}, keys, w); err != nil {
		t.Fatal(err)
	}
	if p.deletes != 0 {
		t.Fatal("delete retried after old key was already absent")
	}
	if got := s.Snapshot().Workflows[model.WorkflowKey(w.Zone, w.Kind)].Phase; got != model.PhaseIdle {
		t.Fatalf("phase=%s", got)
	}
}
