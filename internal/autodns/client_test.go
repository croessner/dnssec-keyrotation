package autodns

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/croessner/dnssec-keyrotation/internal/model"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUpdateDNSSECSendsOnlyPublicMaterial(t *testing.T) {
	var body map[string]any
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "api-dnssec" || p != "secret" {
			t.Error("bad auth")
		}
		if r.Header.Get("X-Domainrobot-Context") != "4" {
			t.Error("bad context")
		}
		if r.Header.Get("X-Domainrobot-Ctid") != "ctid-1234567890" {
			t.Error("bad ctid")
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		response := `{"stid":"tx-1","status":{"code":"N0102","type":"NOTIFY"},"data":[{"id":4297543151,"status":"RUNNING"}]}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
	})}
	c := New("https://api.test/v1", "api-dnssec", "secret", 4, 0, hc)
	job, err := c.UpdateDNSSEC(context.Background(), "example.test.", []model.DNSSECData{{Flags: 257, Protocol: 3, Algorithm: 13, PublicKey: "AAAA"}}, "ctid-1234567890")
	if err != nil {
		t.Fatal(err)
	}
	if job.STID != "tx-1" || job.ID != 4297543151 || job.Status != "RUNNING" {
		t.Fatalf("job=%+v", job)
	}
	if body["name"] != "example.test" {
		t.Fatalf("body=%v", body)
	}
	if body["dnssec"] != true {
		t.Fatalf("dnssec flag missing: %v", body)
	}
	if _, ok := body["privateKey"]; ok {
		t.Fatal("private key field sent")
	}
}

func TestJobStatusUsesOfficialNestedJobShape(t *testing.T) {
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/job/4297543151" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		fixture := `{"status":{"code":"S300114","type":"SUCCESS"},"data":[{"job":{"id":4297543151,"status":"SUCCESS"}}]}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fixture)), Header: make(http.Header)}, nil
	})}
	c := New("https://api.test/v1", "user", "secret", 4, 0, hc)
	got, err := c.JobStatus(context.Background(), 4297543151)
	if err != nil {
		t.Fatal(err)
	}
	if got != "SUCCESS" {
		t.Fatalf("status=%q", got)
	}
}

func TestDomainInfoOfficialDNSSECShape(t *testing.T) {
	hc := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		fixture := `{"status":{"resultCode":"S0105","type":"SUCCESS"},"data":[{"name":"example.test","dnssec":true,"dnssecData":[{"flags":257,"protocol":3,"algorithm":13,"publicKey":"AQID"}]}]}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fixture)), Header: make(http.Header)}, nil
	})}
	c := New("https://api.test/v1", "user", "secret", 4, 0, hc)
	got, err := c.DomainDNSSEC(context.Background(), "example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || len(got.Data) != 1 || got.Data[0].PublicKey != "AQID" {
		t.Fatalf("unexpected material: %+v", got)
	}
}

func TestDomainInfoPreservesDisabledEmptyDNSSECState(t *testing.T) {
	hc := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		fixture := `{"status":{"resultCode":"S0105","type":"SUCCESS"},"data":[{"name":"example.test","dnssec":false,"dnssecData":[]}]}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fixture)), Header: make(http.Header)}, nil
	})}
	c := New("https://api.test/v1", "user", "secret", 4, 0, hc)
	got, err := c.DomainDNSSEC(context.Background(), "example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled || len(got.Data) != 0 {
		t.Fatalf("unexpected state: %+v", got)
	}
}

func TestDomainInfoRejectsMissingInitialEnrollmentFields(t *testing.T) {
	for name, domain := range map[string]string{
		"missing dnssec":        `{"dnssecData":[]}`,
		"missing dnssecData":    `{"dnssec":false}`,
		"null dnssec only":      `{"dnssec":null}`,
		"null dnssecData":       `{"dnssec":false,"dnssecData":null}`,
		"both null":             `{"dnssec":null,"dnssecData":null}`,
		"wrong dnssecData type": `{"dnssec":false,"dnssecData":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			hc := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				fixture := `{"status":{"resultCode":"S0105","type":"SUCCESS"},"data":[` + domain + `]}`
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fixture)), Header: make(http.Header)}, nil
			})}
			c := New("https://api.test/v1", "user", "secret", 4, 0, hc)
			if _, err := c.DomainDNSSEC(context.Background(), "example.test."); err == nil {
				t.Fatal("malformed registrar state was accepted")
			}
		})
	}
}

func TestDomainInfoAcceptsDocumentedOmittedDNSSECState(t *testing.T) {
	hc := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		fixture := `{"status":{"resultCode":"S0105","type":"SUCCESS"},"data":[{"name":"example.test"}]}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fixture)), Header: make(http.Header)}, nil
	})}
	c := New("https://api.test/v1", "user", "secret", 4, 0, hc)
	got, err := c.DomainDNSSEC(context.Background(), "example.test.")
	if err != nil {
		t.Fatalf("documented optional DNSSEC fields should classify as disabled-empty: %v", err)
	}
	if got.Enabled || len(got.Data) != 0 || !got.Omitted {
		t.Fatalf("unexpected omitted state: %+v", got)
	}
}

func TestDomainInfoRejectsMismatchedDomainName(t *testing.T) {
	hc := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		fixture := `{"status":{"resultCode":"S0105","type":"SUCCESS"},"data":[{"name":"other.test","dnssec":false,"dnssecData":[]}]}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fixture)), Header: make(http.Header)}, nil
	})}
	c := New("https://api.test/v1", "user", "secret", 4, 0, hc)
	if _, err := c.DomainDNSSEC(context.Background(), "example.test."); err == nil {
		t.Fatal("mismatched registrar domain was accepted")
	}
}
