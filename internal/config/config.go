// Package config loads and validates controller configuration and secret files.
package config

import (
	"errors"
	"fmt"
	"net"
	mailpkg "net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// Config contains the complete validated controller configuration.
type Config struct {
	Mode          string        `mapstructure:"mode"`
	Log           Log           `mapstructure:"log"`
	Controller    Controller    `mapstructure:"controller"`
	PowerDNS      PowerDNS      `mapstructure:"powerdns"`
	AutoDNS       AutoDNS       `mapstructure:"autodns"`
	DNS           DNS           `mapstructure:"dns"`
	Rotation      Rotation      `mapstructure:"rotation"`
	Enrollment    Enrollment    `mapstructure:"enrollment"`
	Notifications Notifications `mapstructure:"notifications"`
}

// Log configures structured logging.
type Log struct {
	Level string `mapstructure:"level"`
}

// Controller configures reconciliation, persistence, and the control socket.
type Controller struct {
	ReconcileInterval    time.Duration `mapstructure:"reconcile_interval"`
	PropagationMargin    time.Duration `mapstructure:"propagation_margin"`
	StateFile            string        `mapstructure:"state_file"`
	Socket               string        `mapstructure:"socket"`
	IdempotencyRetention time.Duration `mapstructure:"idempotency_retention"`
}

// PowerDNS configures access to the local PowerDNS API.
type PowerDNS struct {
	URL        string        `mapstructure:"url"`
	ServerID   string        `mapstructure:"server_id"`
	APIKeyFile string        `mapstructure:"api_key_file"`
	Timeout    time.Duration `mapstructure:"timeout"`
}

// AutoDNS configures access to the registrar API.
type AutoDNS struct {
	URL                    string        `mapstructure:"url"`
	Username               string        `mapstructure:"username"`
	PasswordFile           string        `mapstructure:"password_file"`
	Context                int           `mapstructure:"context"`
	Timeout                time.Duration `mapstructure:"timeout"`
	MinimumRequestInterval time.Duration `mapstructure:"minimum_request_interval"`
}

// DNS configures independent recursive and authoritative evidence paths.
type DNS struct {
	Resolvers            []string      `mapstructure:"resolvers"`
	AuthoritativeServers []string      `mapstructure:"authoritative_servers"`
	ExpectedNameservers  []string      `mapstructure:"expected_nameservers"`
	LocalAuthoritative   string        `mapstructure:"local_authoritative"`
	Timeout              time.Duration `mapstructure:"timeout"`
}

// Rotation configures key cadence and propagation safety margins.
type Rotation struct {
	Algorithm         string        `mapstructure:"algorithm"`
	ZSKInterval       time.Duration `mapstructure:"zsk_interval"`
	KSKInterval       time.Duration `mapstructure:"ksk_interval"`
	AutoMigrateCSK    bool          `mapstructure:"auto_migrate_csk"`
	MinimumDNSKEYWait time.Duration `mapstructure:"minimum_dnskey_wait"`
	MinimumParentWait time.Duration `mapstructure:"minimum_parent_wait"`
	IncludeZones      []string      `mapstructure:"include_zones"`
	ExcludeZones      []string      `mapstructure:"exclude_zones"`
}

// Enrollment configures guarded automatic initial delegation enrollment.
type Enrollment struct {
	Enabled           bool          `mapstructure:"enabled"`
	Scope             string        `mapstructure:"scope"`
	DiscoveryGrace    time.Duration `mapstructure:"discovery_grace"`
	MaxPending        int           `mapstructure:"max_pending"`
	MaxNewPerDay      int           `mapstructure:"max_new_per_day"`
	AllowedAlgorithms []string      `mapstructure:"allowed_algorithms"`
	IncludeZones      []string      `mapstructure:"include_zones"`
	ExcludeZones      []string      `mapstructure:"exclude_zones"`
}

// Notifications configures durable completion delivery.
type Notifications struct {
	LMTP LMTP `mapstructure:"lmtp"`
}

// LMTP configures the completion-report transport.
type LMTP struct {
	Enabled  bool          `mapstructure:"enabled"`
	Address  string        `mapstructure:"address"`
	Hostname string        `mapstructure:"hostname"`
	From     string        `mapstructure:"from"`
	To       []string      `mapstructure:"to"`
	Timeout  time.Duration `mapstructure:"timeout"`
}

// Load reads and validates a controller configuration file.
func Load(path string) (Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvPrefix("DNSSEC_ROTATION")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	setDefaults(v)
	if err := v.ReadInConfig(); err != nil {
		return Config{}, err
	}
	var c Config
	if err := v.Unmarshal(&c); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("mode", "observe")
	v.SetDefault("log.level", "info")
	v.SetDefault("controller.reconcile_interval", "1m")
	v.SetDefault("controller.propagation_margin", "2h")
	v.SetDefault("controller.state_file", "/var/lib/dnssec-keyrotation/state.json")
	v.SetDefault("controller.socket", "/run/dnssec-keyrotation/control.sock")
	v.SetDefault("controller.idempotency_retention", "8760h")
	v.SetDefault("powerdns.server_id", "localhost")
	v.SetDefault("powerdns.timeout", "10s")
	v.SetDefault("autodns.url", "https://api.autodns.com/v1")
	v.SetDefault("autodns.context", 4)
	v.SetDefault("autodns.timeout", "20s")
	v.SetDefault("autodns.minimum_request_interval", "500ms")
	v.SetDefault("dns.timeout", "5s")
	v.SetDefault("dns.local_authoritative", "127.0.0.1:53")
	v.SetDefault("rotation.algorithm", "ECDSAP256SHA256")
	v.SetDefault("rotation.zsk_interval", "720h")
	v.SetDefault("rotation.ksk_interval", "4368h")
	v.SetDefault("rotation.minimum_dnskey_wait", "24h")
	v.SetDefault("rotation.minimum_parent_wait", "48h")
	v.SetDefault("enrollment.enabled", false)
	v.SetDefault("enrollment.scope", "none")
	v.SetDefault("enrollment.discovery_grace", "24h")
	v.SetDefault("enrollment.max_pending", 10)
	v.SetDefault("enrollment.max_new_per_day", 5)
	v.SetDefault("enrollment.allowed_algorithms", []string{"ECDSAP256SHA256"})
	v.SetDefault("notifications.lmtp.enabled", false)
	v.SetDefault("notifications.lmtp.timeout", "10s")
}

// Validate enforces fail-closed configuration constraints.
func (c Config) Validate() error {
	if c.Mode != "observe" && c.Mode != "enforce" {
		return errors.New("mode must be observe or enforce")
	}
	if c.Controller.ReconcileInterval < 10*time.Second {
		return errors.New("reconcile interval must be at least 10s")
	}
	if c.Controller.PropagationMargin < time.Minute {
		return errors.New("propagation margin must be at least 1m")
	}
	if c.Controller.IdempotencyRetention < 24*time.Hour {
		return errors.New("idempotency retention must be at least 24h")
	}
	if !filepath.IsAbs(c.Controller.StateFile) || !filepath.IsAbs(c.Controller.Socket) {
		return errors.New("state_file and socket must be absolute")
	}
	if !pathWithin(c.Controller.StateFile, "/var/lib/dnssec-keyrotation") {
		return errors.New("state_file must be under /var/lib/dnssec-keyrotation")
	}
	if !pathWithin(c.Controller.Socket, "/run/dnssec-keyrotation") {
		return errors.New("socket must be under /run/dnssec-keyrotation")
	}
	p, err := url.Parse(c.PowerDNS.URL)
	if err != nil || p.Scheme != "http" {
		return errors.New("powerdns.url must be a valid loopback http URL")
	}
	host := p.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("powerdns.url must use loopback; remote plaintext API access is forbidden")
	}
	a, err := url.Parse(c.AutoDNS.URL)
	if err != nil || a.Scheme != "https" || a.Host == "" {
		return errors.New("autodns.url must be HTTPS")
	}
	if a.Hostname() != "api.autodns.com" && a.Hostname() != "api.demo.autodns.com" {
		return errors.New("autodns.url host is not an approved DomainRobot endpoint")
	}
	for _, p := range []string{c.PowerDNS.APIKeyFile, c.AutoDNS.PasswordFile} {
		clean := filepath.Clean(p)
		if !strings.HasPrefix(clean, "/run/secrets/") {
			return fmt.Errorf("secret path %s must be under /run/secrets", p)
		}
	}
	if c.AutoDNS.Context <= 0 || c.AutoDNS.Username == "" {
		return errors.New("autodns username and positive context are required")
	}
	if c.AutoDNS.MinimumRequestInterval < 334*time.Millisecond {
		return errors.New("autodns minimum request interval must stay below 3 requests/s")
	}
	if len(c.DNS.Resolvers) < 2 {
		return errors.New("at least two independent DNS resolvers are required")
	}
	seenResolvers := map[string]bool{}
	for _, r := range c.DNS.Resolvers {
		if _, _, err := net.SplitHostPort(r); err != nil {
			return fmt.Errorf("invalid resolver %q: %w", r, err)
		}
		if seenResolvers[r] {
			return fmt.Errorf("duplicate resolver %q", r)
		}
		seenResolvers[r] = true
	}
	if _, _, err := net.SplitHostPort(c.DNS.LocalAuthoritative); err != nil {
		return fmt.Errorf("invalid local authoritative address: %w", err)
	}
	if len(c.DNS.AuthoritativeServers) < 2 {
		return errors.New("at least two authoritative servers are required")
	}
	if c.Enrollment.Enabled && len(c.DNS.ExpectedNameservers) < 2 {
		return errors.New("automatic enrollment requires at least two expected parent nameservers")
	}
	seenNS := map[string]bool{}
	for _, server := range c.DNS.ExpectedNameservers {
		name := strings.ToLower(dns.Fqdn(strings.TrimSpace(server)))
		if _, ok := dns.IsDomainName(name); !ok || seenNS[name] {
			return fmt.Errorf("invalid or duplicate expected nameserver %q", server)
		}
		seenNS[name] = true
	}
	if c.Enrollment.Enabled {
		if len(c.DNS.AuthoritativeServers) != len(seenNS) {
			return errors.New("automatic enrollment requires authoritative_servers to match expected_nameservers exactly")
		}
		for _, endpoint := range c.DNS.AuthoritativeServers {
			host, _, err := net.SplitHostPort(endpoint)
			if err != nil || net.ParseIP(host) != nil || !seenNS[strings.ToLower(dns.Fqdn(host))] {
				return fmt.Errorf("authoritative server %q is not an expected delegated nameserver", endpoint)
			}
		}
	}
	if c.Rotation.ZSKInterval < 24*time.Hour || c.Rotation.KSKInterval < 30*24*time.Hour {
		return errors.New("rotation intervals are below policy minimum")
	}
	if c.Rotation.MinimumDNSKEYWait < time.Hour || c.Rotation.MinimumParentWait < 48*time.Hour {
		return errors.New("minimum DNSSEC evidence waits are below policy minimum")
	}
	if c.Rotation.AutoMigrateCSK {
		return errors.New("automatic CSK migration is forbidden; use an explicit confirmed split trigger")
	}
	if c.Enrollment.Scope != "none" && c.Enrollment.Scope != "all_selected" {
		return errors.New("enrollment scope must be none or all_selected")
	}
	if c.Enrollment.Enabled && c.Enrollment.Scope != "all_selected" {
		return errors.New("enabled enrollment requires explicit scope all_selected")
	}
	if c.Enrollment.DiscoveryGrace < 24*time.Hour {
		return errors.New("enrollment discovery grace must be at least 24h")
	}
	if c.Enrollment.MaxPending < 1 || c.Enrollment.MaxPending > 100 || c.Enrollment.MaxNewPerDay < 1 || c.Enrollment.MaxNewPerDay > 100 {
		return errors.New("enrollment circuit-breaker limits must be between 1 and 100")
	}
	if len(c.Enrollment.AllowedAlgorithms) == 0 {
		return errors.New("enrollment allowed_algorithms must not be empty")
	}
	if c.Notifications.LMTP.Enabled {
		host, _, err := net.SplitHostPort(c.Notifications.LMTP.Address)
		if err != nil {
			return fmt.Errorf("invalid LMTP address: %w", err)
		}
		ip := net.ParseIP(host)
		if ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
			return errors.New("LMTP address must be a private or loopback IP")
		}
		if c.Notifications.LMTP.Hostname == "" || strings.ContainsAny(c.Notifications.LMTP.Hostname, "\r\n") {
			return errors.New("LMTP hostname is required and must not contain line breaks")
		}
		if _, ok := dns.IsDomainName(dns.Fqdn(c.Notifications.LMTP.Hostname)); !ok {
			return errors.New("LMTP hostname must be a valid DNS name")
		}
		if c.Notifications.LMTP.Timeout < time.Second || c.Notifications.LMTP.Timeout > time.Minute {
			return errors.New("LMTP timeout must be between 1s and 1m")
		}
		if _, err := parseMailbox(c.Notifications.LMTP.From); err != nil {
			return fmt.Errorf("invalid LMTP sender: %w", err)
		}
		if len(c.Notifications.LMTP.To) == 0 {
			return errors.New("at least one LMTP recipient is required")
		}
		for _, recipient := range c.Notifications.LMTP.To {
			if _, err := parseMailbox(recipient); err != nil {
				return fmt.Errorf("invalid LMTP recipient: %w", err)
			}
		}
	}
	return nil
}

// ReadSecret reads a restricted regular file without following symlinks.
func ReadSecret(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("secret %s must be a regular non-symlink file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("secret %s must not be group/world accessible", path)
	}
	// #nosec G304 -- Validate restricts both secret paths to /run/secrets and
	// Lstat above rejects symlinks and non-regular files before the read.
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	for i := range b {
		b[i] = 0
	}
	if s == "" {
		return "", fmt.Errorf("secret %s is empty", path)
	}
	return s, nil
}

func pathWithin(path, root string) bool {
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(root, clean)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func parseMailbox(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", errors.New("mailbox must not contain line breaks")
	}
	address, err := mailpkg.ParseAddress(value)
	if err != nil {
		return "", err
	}
	if address.Address == "" {
		return "", errors.New("mailbox address is empty")
	}
	return address.Address, nil
}
