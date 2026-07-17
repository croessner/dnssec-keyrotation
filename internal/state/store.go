// Package state provides locked, atomic persistence for controller workflows.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/croessner/dnssec-keyrotation/internal/model"
	"golang.org/x/sys/unix"
)

// Store owns the process lock and current persisted controller state.
type Store struct {
	mu   sync.Mutex
	path string
	data model.State
	lock *os.File
}

const currentVersion = 3

// Open acquires the exclusive state lock and loads or migrates persisted state.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// #nosec G304 -- path is the controller state path validated by config;
	// tests may deliberately inject a temporary absolute path.
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- on Unix an open file descriptor is representable as int;
	// os.File.Fd returns uintptr for portability only.
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("state is locked by another controller: %w", err)
	}
	s := &Store{path: path, lock: lock, data: model.State{Version: currentVersion, Workflows: map[string]model.Workflow{}, Idempotency: map[string]string{}, Notifications: map[string]model.Notification{}}}
	// #nosec G304 -- see the validated state path above.
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = s.Close()
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &s.data); err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("decode state: %w", err)
		}
		if s.data.Version < 1 || s.data.Version > currentVersion {
			_ = s.Close()
			return nil, fmt.Errorf("unsupported state version %d", s.data.Version)
		}
	}
	if s.data.Workflows == nil {
		s.data.Workflows = map[string]model.Workflow{}
	}
	if s.data.Idempotency == nil {
		s.data.Idempotency = map[string]string{}
	}
	if s.data.Notifications == nil {
		s.data.Notifications = map[string]model.Notification{}
	}
	if s.data.Version < currentVersion {
		oldVersion := s.data.Version
		s.data.Version = currentVersion
		if err := writeAtomic(path, s.data); err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("persist state v%d to v%d migration: %w", oldVersion, currentVersion, err)
		}
	}
	return s, nil
}

// Close releases the state lock.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	// #nosec G115 -- see the descriptor rationale in Open.
	_ = unix.Flock(int(s.lock.Fd()), unix.LOCK_UN)
	err := s.lock.Close()
	s.lock = nil
	return err
}

// Snapshot returns an isolated copy of the current state.
func (s *Store) Snapshot() model.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := cloneState(s.data)
	return out
}

func cloneState(in model.State) model.State {
	out := model.State{Version: in.Version, EnrollmentArmedAt: in.EnrollmentArmedAt, Workflows: make(map[string]model.Workflow, len(in.Workflows)), Idempotency: make(map[string]string, len(in.Idempotency)), Notifications: make(map[string]model.Notification, len(in.Notifications))}
	for k, v := range in.Workflows {
		out.Workflows[k] = v
	}
	for k, v := range in.Idempotency {
		out.Idempotency[k] = v
	}
	for k, v := range in.Notifications {
		out.Notifications[k] = v
	}
	return out
}

// Update applies one mutation and atomically persists it before publication.
func (s *Store) Update(fn func(*model.State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := cloneState(s.data)
	if err := fn(&clone); err != nil {
		return err
	}
	if err := writeAtomic(s.path, clone); err != nil {
		return err
	}
	s.data = clone
	return nil
}

func writeAtomic(path string, data model.State) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	// #nosec G304 -- dir is derived from the validated state path.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	if err := d.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
