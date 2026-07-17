// Package autodns provides the registrar integration used for parent DNSSEC material.
package autodns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/croessner/dnssec-keyrotation/internal/model"
)

// API defines the registrar operations used by the controller.
type API interface {
	DomainDNSSEC(context.Context, string) (DomainDNSSECState, error)
	UpdateDNSSEC(context.Context, string, []model.DNSSECData, string) (Job, error)
	JobStatus(context.Context, int64) (string, error)
}

// DomainDNSSECState describes the registrar's current DNSSEC configuration.
type DomainDNSSECState struct {
	Enabled bool
	Data    []model.DNSSECData
	Omitted bool
}

// Job identifies an asynchronous registrar operation.
type Job struct {
	ID     int64
	STID   string
	Status string
}

// Client implements the registrar API with bounded request pacing.
type Client struct {
	base, username, password string
	context                  int
	http                     *http.Client
	minimumInterval          time.Duration
	mu                       sync.Mutex
	last                     time.Time
}

type response struct {
	STID   string `json:"stid"`
	Status struct {
		Code       string `json:"code"`
		ResultCode string `json:"resultCode"`
		Text       string `json:"text"`
		Type       string `json:"type"`
	} `json:"status"`
	Data []json.RawMessage `json:"data"`
}

// New creates a registrar API client.
func New(base, username, password string, contextNumber int, minimumInterval time.Duration, hc *http.Client) *Client {
	return &Client{base: strings.TrimRight(base, "/"), username: username, password: password, context: contextNumber, minimumInterval: minimumInterval, http: hc}
}

// DomainDNSSEC reads the registrar DNSSEC state for a zone.
func (c *Client) DomainDNSSEC(ctx context.Context, zone string) (DomainDNSSECState, error) {
	var r response
	path := "/domain/" + url.PathEscape(strings.TrimSuffix(zone, "."))
	if err := c.do(ctx, http.MethodGet, path, nil, "", &r); err != nil {
		return DomainDNSSECState{}, err
	}
	if len(r.Data) != 1 {
		return DomainDNSSECState{}, fmt.Errorf("autodns domain info returned %d records", len(r.Data))
	}
	var d struct {
		Name       string          `json:"name"`
		DNSSECData json.RawMessage `json:"dnssecData"`
		DNSSEC     json.RawMessage `json:"dnssec"`
	}
	if err := json.Unmarshal(r.Data[0], &d); err != nil {
		return DomainDNSSECState{}, fmt.Errorf("decode autodns domain info: %w", err)
	}
	requested := strings.ToLower(strings.TrimSuffix(zone, "."))
	if strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.Name), ".")) != requested {
		return DomainDNSSECState{}, fmt.Errorf("decode autodns domain info: returned domain name does not match request")
	}
	dnssecRaw := bytes.TrimSpace(d.DNSSEC)
	dataRaw := bytes.TrimSpace(d.DNSSECData)
	if len(dnssecRaw) == 0 && len(dataRaw) == 0 {
		return DomainDNSSECState{Data: []model.DNSSECData{}, Omitted: true}, nil
	}
	if len(dnssecRaw) == 0 {
		return DomainDNSSECState{}, fmt.Errorf("decode autodns domain info: dnssec field is missing")
	}
	if len(dataRaw) == 0 {
		return DomainDNSSECState{}, fmt.Errorf("decode autodns domain info: dnssecData field is missing")
	}
	var enabled bool
	if bytes.Equal(dnssecRaw, []byte("null")) || json.Unmarshal(dnssecRaw, &enabled) != nil {
		return DomainDNSSECState{}, fmt.Errorf("decode autodns domain info: dnssec must be an explicit boolean")
	}
	if dataRaw[0] != '[' {
		return DomainDNSSECState{}, fmt.Errorf("decode autodns domain info: dnssecData must be an explicit array")
	}
	var data []model.DNSSECData
	if err := json.Unmarshal(dataRaw, &data); err != nil {
		return DomainDNSSECState{}, fmt.Errorf("decode autodns domain info dnssecData: %w", err)
	}
	if data == nil {
		return DomainDNSSECState{}, fmt.Errorf("decode autodns domain info: dnssecData must not be null")
	}
	return DomainDNSSECState{Enabled: enabled, Data: data}, nil
}

// UpdateDNSSEC replaces the registrar's public DNSSEC material idempotently.
func (c *Client) UpdateDNSSEC(ctx context.Context, zone string, keys []model.DNSSECData, ctid string) (Job, error) {
	body := map[string]any{"name": strings.TrimSuffix(zone, "."), "dnssec": true, "dnssecData": keys}
	var r response
	path := "/domain/" + url.PathEscape(strings.TrimSuffix(zone, "."))
	if err := c.do(ctx, http.MethodPut, path, body, ctid, &r); err != nil {
		return Job{}, err
	}
	job := Job{STID: r.STID, Status: strings.ToUpper(r.Status.Type)}
	if len(r.Data) > 0 {
		var data struct {
			ID     int64  `json:"id"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(r.Data[0], &data); err != nil {
			return Job{}, fmt.Errorf("decode autodns job acknowledgement: %w", err)
		}
		job.ID = data.ID
		if data.Status != "" {
			job.Status = strings.ToUpper(data.Status)
		}
	}
	if strings.EqualFold(r.Status.Type, "NOTIFY") && job.ID == 0 {
		return Job{}, fmt.Errorf("autodns asynchronous response omitted job id")
	}
	return job, nil
}

// JobStatus returns the current state of an asynchronous registrar job.
func (c *Client) JobStatus(ctx context.Context, id int64) (string, error) {
	if id <= 0 {
		return "", fmt.Errorf("autodns job id must be positive")
	}
	var r response
	if err := c.do(ctx, http.MethodGet, "/job/"+fmt.Sprint(id), nil, "", &r); err != nil {
		return "", err
	}
	if len(r.Data) != 1 {
		return "", fmt.Errorf("autodns job info returned %d records", len(r.Data))
	}
	var data struct {
		Job struct {
			ID     int64  `json:"id"`
			Status string `json:"status"`
		} `json:"job"`
	}
	if err := json.Unmarshal(r.Data[0], &data); err != nil {
		return "", fmt.Errorf("decode autodns job info: %w", err)
	}
	if data.Job.ID != id || data.Job.Status == "" {
		return "", fmt.Errorf("autodns job info did not identify requested job %d", id)
	}
	return strings.ToUpper(data.Job.Status), nil
}

func (c *Client) do(ctx context.Context, method, path string, body any, ctid string, out any) error {
	c.mu.Lock()
	wait := c.minimumInterval - time.Since(c.last)
	if wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			c.mu.Unlock()
			return ctx.Err()
		case <-t.C:
		}
	}
	c.last = time.Now()
	c.mu.Unlock()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("X-Domainrobot-Context", fmt.Sprint(c.context))
	if ctid != "" {
		req.Header.Set("X-Domainrobot-Ctid", ctid)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("autodns %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	limited := io.LimitReader(resp.Body, 1<<20)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(limited)
		var e response
		_ = json.Unmarshal(b, &e)
		msg := e.Status.Text
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		code := e.Status.Code
		if code == "" {
			code = e.Status.ResultCode
		}
		return fmt.Errorf("autodns %s %s: status %d code %s: %s", method, path, resp.StatusCode, code, msg)
	}
	if err := json.NewDecoder(limited).Decode(out); err != nil {
		return fmt.Errorf("decode autodns response: %w", err)
	}
	if r, ok := out.(*response); ok && strings.EqualFold(r.Status.Type, "ERROR") {
		code := r.Status.Code
		if code == "" {
			code = r.Status.ResultCode
		}
		return fmt.Errorf("autodns code %s: %s", code, r.Status.Text)
	}
	return nil
}
