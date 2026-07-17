package pdns

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestListKeysDropsPrivateMaterial(t *testing.T) {
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-API-Key") != "secret" {
			t.Error("missing api key")
		}
		body := `[{"id":1,"keytype":"ksk","active":true,"published":true,"privatekey":"must-not-escape","dnskey":"257 3 13 AAAA","algorithm":"ECDSAP256SHA256"}]`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	c := New("http://127.0.0.1", "localhost", "secret", hc)
	keys, err := c.ListKeys(context.Background(), "example.test.")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(keys)
	if strings.Contains(string(b), "must-not-escape") {
		t.Fatalf("private material escaped: %s", b)
	}
}
