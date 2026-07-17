package dnsprobe

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveInitialDelegationNoDSEvidence(t *testing.T) {
	if os.Getenv("DNSSEC_LIVE_TEST") != "1" {
		t.Skip("set DNSSEC_LIVE_TEST=1 for the production read-only evidence check")
	}
	p := New(
		[]string{"192.0.2.1:53", "198.51.100.1:53"},
		[]string{"192.0.2.53:53", "198.51.100.53:53"},
		"127.0.0.1:53",
		5*time.Second,
	)
	for _, zone := range []string{"example.test.", "example.invalid."} {
		t.Run(zone, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := p.NoDSEvidence(ctx, zone); err != nil {
				t.Fatal(err)
			}
		})
	}
}
