package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadSecretRejectsBroadPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte("value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret(p); err == nil {
		t.Fatal("expected insecure permission rejection")
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSecret(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != "value" {
		t.Fatalf("got %q", got)
	}
}

func TestValidateRejectsRemotePlaintextPowerDNS(t *testing.T) {
	c := validConfig()
	c.PowerDNS.URL = "http://192.0.2.1:8081/api/v1"
	if err := c.Validate(); err == nil {
		t.Fatal("expected remote plaintext PowerDNS URL rejection")
	}
}

func TestValidateRejectsParentWaitBelowPolicyFloor(t *testing.T) {
	c := validConfig()
	c.Rotation.MinimumParentWait = 24 * time.Hour
	if err := c.Validate(); err == nil {
		t.Fatal("expected parent wait below 48h to be rejected")
	}
}

func TestValidConfig(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateLMTPRequiresPrivateAddressAndSafeMailboxes(t *testing.T) {
	c := validConfig()
	c.Notifications.LMTP = LMTP{Enabled: true, Address: "203.0.113.5:24", Hostname: "ns1.example.net", From: "dnssec@example.net", To: []string{"admin@example.net"}, Timeout: 10 * time.Second}
	if err := c.Validate(); err == nil {
		t.Fatal("public LMTP destination accepted")
	}
	c.Notifications.LMTP.Address = "192.0.2.50:24"
	c.Notifications.LMTP.To = []string{"admin@example.net\r\nBcc: attacker@example.net"}
	if err := c.Validate(); err == nil {
		t.Fatal("LMTP header injection accepted")
	}
}

func TestValidateEnrollmentBindsDelegationNamesToAuthoritativeEvidenceEndpoints(t *testing.T) {
	c := validConfig()
	c.Enrollment.Enabled = true
	c.Enrollment.Scope = "all_selected"
	if err := c.Validate(); err == nil {
		t.Fatal("IP-only authoritative endpoints were accepted for automatic enrollment")
	}
	c.DNS.AuthoritativeServers = []string{"ns1.example.net:53", "ns2.example.net:53"}
	if err := c.Validate(); err != nil {
		t.Fatalf("exact delegation/evidence binding rejected: %v", err)
	}
}

func validConfig() Config {
	return Config{
		Mode:       "observe",
		Controller: Controller{ReconcileInterval: time.Minute, PropagationMargin: time.Minute, StateFile: "/var/lib/dnssec-keyrotation/state", Socket: "/run/dnssec-keyrotation/control.sock", IdempotencyRetention: 365 * 24 * time.Hour},
		PowerDNS:   PowerDNS{URL: "http://127.0.0.1:8081/api/v1", APIKeyFile: "/run/secrets/pdns_api_key"},
		AutoDNS:    AutoDNS{URL: "https://api.autodns.com/v1", Username: "user", PasswordFile: "/run/secrets/autodns_password", Context: 4, MinimumRequestInterval: 500 * time.Millisecond},
		DNS:        DNS{Resolvers: []string{"192.0.2.1:53", "198.51.100.1:53"}, AuthoritativeServers: []string{"192.0.2.53:53", "198.51.100.53:53"}, ExpectedNameservers: []string{"ns1.example.net", "ns2.example.net"}, LocalAuthoritative: "127.0.0.1:53", Timeout: 5 * time.Second},
		Rotation:   Rotation{ZSKInterval: 30 * 24 * time.Hour, KSKInterval: 182 * 24 * time.Hour, MinimumDNSKEYWait: 24 * time.Hour, MinimumParentWait: 48 * time.Hour},
		Enrollment: Enrollment{Scope: "none", DiscoveryGrace: 24 * time.Hour, MaxPending: 10, MaxNewPerDay: 5, AllowedAlgorithms: []string{"ECDSAP256SHA256"}},
	}
}
