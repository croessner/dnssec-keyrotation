// Package pdns provides the PowerDNS API boundary used by the controller.
package pdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/croessner/dnssec-keyrotation/internal/model"
)

// API defines the PowerDNS operations used by the controller.
type API interface {
	ListZones(context.Context) ([]model.Zone, error)
	GetZone(context.Context, string) (model.Zone, error)
	ListKeys(context.Context, string) ([]model.Key, error)
	CreateKey(context.Context, string, string, string, bool) (model.Key, error)
	SetKey(context.Context, string, model.Key, bool, bool) error
	DeleteKey(context.Context, string, int) error
}

// Client implements the PowerDNS HTTP API.
type Client struct {
	base, serverID, apiKey string
	http                   *http.Client
}

// New creates a PowerDNS API client.
func New(base, serverID, apiKey string, hc *http.Client) *Client {
	return &Client{base: strings.TrimRight(base, "/"), serverID: serverID, apiKey: apiKey, http: hc}
}

// ListZones returns every zone visible to the configured PowerDNS server.
func (c *Client) ListZones(ctx context.Context) ([]model.Zone, error) {
	var out []model.Zone
	err := c.do(ctx, http.MethodGet, "/servers/"+url.PathEscape(c.serverID)+"/zones", nil, &out)
	return out, err
}

// GetZone returns one PowerDNS zone and its metadata.
func (c *Client) GetZone(ctx context.Context, zoneID string) (model.Zone, error) {
	var out model.Zone
	err := c.do(ctx, http.MethodGet, "/servers/"+url.PathEscape(c.serverID)+"/zones/"+url.PathEscape(zoneID), nil, &out)
	return out, err
}

// ListKeys returns the DNSSEC key inventory for a zone.
func (c *Client) ListKeys(ctx context.Context, zoneID string) ([]model.Key, error) {
	var out []model.Key
	err := c.do(ctx, http.MethodGet, c.keysPath(zoneID), nil, &out)
	return out, err
}

// CreateKey creates a published DNSSEC key in PowerDNS.
func (c *Client) CreateKey(ctx context.Context, zoneID, keyType, algorithm string, active bool) (model.Key, error) {
	body := map[string]any{"keytype": keyType, "active": active, "published": true, "algorithm": algorithm}
	var out model.Key
	err := c.do(ctx, http.MethodPost, c.keysPath(zoneID), body, &out)
	return out, err
}

// SetKey updates the active and published state of an existing key.
func (c *Client) SetKey(ctx context.Context, zoneID string, key model.Key, active, published bool) error {
	body := map[string]any{"keytype": key.KeyType, "active": active, "published": published}
	return c.do(ctx, http.MethodPut, c.keysPath(zoneID)+"/"+strconv.Itoa(key.ID), body, nil)
}

// DeleteKey removes an existing key after controller invariants have passed.
func (c *Client) DeleteKey(ctx context.Context, zoneID string, id int) error {
	return c.do(ctx, http.MethodDelete, c.keysPath(zoneID)+"/"+strconv.Itoa(id), nil, nil)
}

func (c *Client) keysPath(zoneID string) string {
	return "/servers/" + url.PathEscape(c.serverID) + "/zones/" + url.PathEscape(zoneID) + "/cryptokeys"
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("powerdns %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	limited := io.LimitReader(resp.Body, 1<<20)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(limited)
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("powerdns %s %s: status %d: %s", method, path, resp.StatusCode, e.Error)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, limited)
		return nil
	}
	if err := json.NewDecoder(limited).Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode powerdns response: %w", err)
	}
	return nil
}
