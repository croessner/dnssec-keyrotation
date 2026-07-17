package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/croessner/dnssec-keyrotation/internal/controller"
	"github.com/croessner/dnssec-keyrotation/internal/model"
)

// Server exposes the local Unix-socket control API.
type Server struct {
	controller *controller.Controller
	path       string
	log        *slog.Logger
	http       *http.Server
}

// New creates a control API server.
func New(c *controller.Controller, path string, log *slog.Logger) *Server {
	s := &Server{controller: c, path: path, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("GET /v1/zones", s.zones)
	mux.HandleFunc("GET /v1/audit", s.audit)
	mux.HandleFunc("POST /v1/rotations/plan", s.plan)
	mux.HandleFunc("POST /v1/rotations/trigger", s.trigger)
	mux.HandleFunc("POST /v1/rotations/resume", s.resume)
	mux.HandleFunc("POST /v1/enrollment/arm", s.armEnrollment)
	s.http = &http.Server{Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	return s
}

// ArmEnrollmentRequest confirms creation of the one-time enrollment baseline.
type ArmEnrollmentRequest struct {
	Confirm bool `json:"confirm"`
}

func (s *Server) armEnrollment(w http.ResponseWriter, r *http.Request) {
	defer func() { _ = r.Body.Close() }()
	d := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	d.DisallowUnknownFields()
	var req ArmEnrollmentRequest
	if err := d.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, errors.New("confirm must be true"))
		return
	}
	idem := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if err := s.controller.ArmEnrollment(r.Context(), idem); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "armed"})
}

// Run prepares the local control socket and serves requests until ctx is canceled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := s.Prepare()
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Prepare creates the protected Unix socket used by the local control API.
func (s *Server) Prepare() (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return nil, err
	}
	if st, err := os.Lstat(s.path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket %s", s.path)
		}
		if err := os.Remove(s.path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve handles control API requests on ln until ctx is canceled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.http.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.http.Shutdown(shutdownCtx)
		_ = os.Remove(s.path)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	st, err := s.controller.Status(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	st, err := s.controller.Status(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}
func (s *Server) zones(w http.ResponseWriter, r *http.Request) {
	z, err := s.controller.Zones(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, z)
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	a, err := s.controller.Audit(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

type request struct {
	Kind    model.Kind `json:"kind"`
	Zones   []string   `json:"zones"`
	Confirm bool       `json:"confirm,omitempty"`
}

func decode(r *http.Request) (request, error) {
	defer func() { _ = r.Body.Close() }()
	d := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	d.DisallowUnknownFields()
	var req request
	if err := d.Decode(&req); err != nil {
		return req, err
	}
	if req.Kind != model.KindZSK && req.Kind != model.KindKSK && req.Kind != model.KindSplit {
		return req, errors.New("kind must be zsk, ksk, or split")
	}
	if len(req.Zones) == 0 {
		return req, errors.New("at least one zone is required")
	}
	if len(req.Zones) > 100 {
		return req, errors.New("at most 100 zones are accepted")
	}
	return req, nil
}
func (s *Server) plan(w http.ResponseWriter, r *http.Request) {
	req, err := decode(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.controller.Plan(req.Kind, req.Zones))
}
func (s *Server) trigger(w http.ResponseWriter, r *http.Request) {
	req, err := decode(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, errors.New("confirm must be true"))
		return
	}
	idem := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if err := s.controller.Trigger(r.Context(), req.Kind, req.Zones, idem); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *Server) resume(w http.ResponseWriter, r *http.Request) {
	defer func() { _ = r.Body.Close() }()
	d := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	d.DisallowUnknownFields()
	var req ResumeRequest
	if err := d.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Kind != model.KindSplit || req.Phase != model.PhaseWaitPublish {
		writeError(w, http.StatusBadRequest, errors.New("only split workflows may be resumed to wait_publish"))
		return
	}
	if len(req.Zones) == 0 || len(req.Zones) > 100 {
		writeError(w, http.StatusBadRequest, errors.New("between one and 100 zones are required"))
		return
	}
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, errors.New("confirm must be true"))
		return
	}
	idem := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if err := s.controller.Resume(r.Context(), req.Kind, req.Zones, req.Phase, idem); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
