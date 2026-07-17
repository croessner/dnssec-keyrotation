package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/dnssec-keyrotation/internal/model"
)

func TestStorePersistsAtomicallyWithPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *model.State) error {
		st.Workflows["x"] = model.Workflow{Zone: "example.test.", Kind: model.KindZSK, Phase: model.PhaseIdle}
		st.Notifications["event-1"] = model.Notification{ID: "event-1", Zone: "example.test.", Kind: model.KindZSK}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode=%o", got)
	}
	_, err = Open(path)
	if err == nil {
		t.Fatal("second store acquired live lock")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Snapshot().Workflows["x"].Zone != "example.test." {
		t.Fatal("state did not survive reopen")
	}
	if again.Snapshot().Notifications["event-1"].Zone != "example.test." {
		t.Fatal("notification outbox did not survive reopen")
	}
	_ = again.Close()
}

func TestOpenMigratesV1ToV3AndPersistsDowngradeGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	v1 := model.State{Version: 1, Workflows: map[string]model.Workflow{"x": {Zone: "example.test.", Kind: model.KindZSK, Phase: model.PhaseIdle}}, Idempotency: map[string]string{}}
	b, err := json.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Snapshot().Version; got != 3 {
		t.Fatalf("version=%d", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var persisted model.State
	b, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Version != 3 || persisted.Notifications == nil {
		t.Fatalf("migration not persisted: %+v", persisted)
	}
}

func TestOpenRejectsFutureStateVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"version":4,"workflows":{},"idempotency":{},"notifications":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("future state version accepted")
	}
}
