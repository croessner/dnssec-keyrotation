package control

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/dnssec-keyrotation/internal/autodns"
	"github.com/croessner/dnssec-keyrotation/internal/config"
	"github.com/croessner/dnssec-keyrotation/internal/controller"
	"github.com/croessner/dnssec-keyrotation/internal/model"
	"github.com/croessner/dnssec-keyrotation/internal/state"
)

type resumePDNS struct {
	zone                   model.Zone
	keys                   []model.Key
	creates, sets, deletes int
}

func (p *resumePDNS) ListZones(context.Context) ([]model.Zone, error) {
	return []model.Zone{p.zone}, nil
}
func (p *resumePDNS) GetZone(context.Context, string) (model.Zone, error)   { return p.zone, nil }
func (p *resumePDNS) ListKeys(context.Context, string) ([]model.Key, error) { return p.keys, nil }
func (p *resumePDNS) CreateKey(context.Context, string, string, string, bool) (model.Key, error) {
	p.creates++
	return model.Key{}, nil
}
func (p *resumePDNS) SetKey(context.Context, string, model.Key, bool, bool) error {
	p.sets++
	return nil
}
func (p *resumePDNS) DeleteKey(context.Context, string, int) error { p.deletes++; return nil }

type resumeRegistrar struct{ updates int }

func (*resumeRegistrar) DomainDNSSEC(context.Context, string) (autodns.DomainDNSSECState, error) {
	return autodns.DomainDNSSECState{Enabled: false}, nil
}
func (r *resumeRegistrar) UpdateDNSSEC(context.Context, string, []model.DNSSECData, string) (autodns.Job, error) {
	r.updates++
	return autodns.Job{}, nil
}
func (*resumeRegistrar) JobStatus(context.Context, int64) (string, error) { return "", nil }

type resumeObserver struct{}

func (*resumeObserver) DNSKEYEvidence(context.Context, string, ...model.Key) (time.Duration, error) {
	return 0, nil
}
func (*resumeObserver) AuthoritativeDNSKEYEvidence(context.Context, string, ...model.Key) (time.Duration, error) {
	return 0, nil
}
func (*resumeObserver) NoDSEvidence(context.Context, string) error            { return nil }
func (*resumeObserver) DSEvidence(context.Context, string, []model.Key) error { return nil }
func (*resumeObserver) AuthoritativeDSEvidence(context.Context, string, []model.Key) (time.Duration, error) {
	return 0, nil
}
func (*resumeObserver) RRSIGBy(context.Context, string, model.Key) error              { return nil }
func (*resumeObserver) AuthoritativeRRSIGBy(context.Context, string, model.Key) error { return nil }
func (*resumeObserver) DNSKEYRRSIGBy(context.Context, string, model.Key) error        { return nil }
func (*resumeObserver) AuthoritativeDNSKEYRRSIGBy(context.Context, string, model.Key) error {
	return nil
}
func (*resumeObserver) DelegationEvidence(context.Context, string, []string) error { return nil }

func TestResumeHandlerPerformsOnlyGuardedStateTransition(t *testing.T) {
	zone := "example.test."
	p := &resumePDNS{
		zone: model.Zone{ID: zone, Name: zone, DNSSEC: true},
		keys: []model.Key{
			{ID: 1, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 AQID"},
			{ID: 2, KeyType: "csk", Active: true, Published: true, DNSKEY: "257 3 13 BAUG"},
			{ID: 3, KeyType: "csk", Active: false, Published: true, DNSKEY: "256 3 13 BwgJ"},
		},
	}
	reg := &resumeRegistrar{}
	st, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	wf := model.Workflow{Zone: zone, Kind: model.KindSplit, Phase: model.PhaseBlocked, ParentMode: "initial", OldKeyID: 1, NewKeyID: 2, NewZSKID: 3}
	if err := st.Update(func(s *model.State) error { s.Workflows[model.WorkflowKey(zone, model.KindSplit)] = wf; return nil }); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Mode: "enforce"}
	c := controller.New(cfg, p, reg, &resumeObserver{}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s := New(c, filepath.Join(t.TempDir(), "control.sock"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	httpServer := httptest.NewServer(s.http.Handler)
	defer httpServer.Close()

	req, err := http.NewRequest(http.MethodPost, httpServer.URL+"/v1/rotations/resume", bytes.NewBufferString(`{"kind":"split","zones":["example.test"],"phase":"wait_publish","confirm":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "resume-handler-test-0001")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if got := st.Snapshot().Workflows[model.WorkflowKey(zone, model.KindSplit)].Phase; got != model.PhaseWaitPublish {
		t.Fatalf("phase=%s", got)
	}
	if p.creates != 0 || p.sets != 0 || p.deletes != 0 || reg.updates != 0 {
		t.Fatalf("external mutation during resume: pdns=%d/%d/%d registrar=%d", p.creates, p.sets, p.deletes, reg.updates)
	}
}
