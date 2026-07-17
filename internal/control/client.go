// Package control provides the Unix-socket control API server and client.
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/croessner/dnssec-keyrotation/internal/model"
)

// Client calls the local Unix-socket control API.
type Client struct{ http *http.Client }

// NewClient creates a control client for the specified Unix socket.
func NewClient(socket string) *Client {
	t := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}, DisableCompression: true, MaxIdleConns: 2, IdleConnTimeout: 10 * time.Second}
	return &Client{http: &http.Client{Transport: t, Timeout: 30 * time.Second}}
}

// Get performs a read-only control API request.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, "", out)
}

// Post performs a control API request with an optional idempotency key.
func (c *Client) Post(ctx context.Context, path string, body any, idem string, out any) error {
	return c.do(ctx, http.MethodPost, path, body, idem, out)
}
func (c *Client) do(ctx context.Context, method, path string, body any, idem string, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	limited := io.LimitReader(resp.Body, 2<<20)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e map[string]string
		_ = json.NewDecoder(limited).Decode(&e)
		return fmt.Errorf("control API status %d: %s", resp.StatusCode, e["error"])
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, limited)
		return nil
	}
	return json.NewDecoder(limited).Decode(out)
}

// RotationRequest is the client payload for planning or triggering a rotation.
type RotationRequest struct {
	Kind    model.Kind `json:"kind"`
	Zones   []string   `json:"zones"`
	Confirm bool       `json:"confirm,omitempty"`
}

// ResumeRequest is the client payload for guarded split-workflow recovery.
type ResumeRequest struct {
	Kind    model.Kind  `json:"kind"`
	Zones   []string    `json:"zones"`
	Phase   model.Phase `json:"phase"`
	Confirm bool        `json:"confirm"`
}
