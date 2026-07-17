// Package dnsprobe collects cryptographic DNSSEC evidence from independent paths.
package dnsprobe

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/croessner/dnssec-keyrotation/internal/model"
	"github.com/miekg/dns"
)

// Observer defines the DNSSEC evidence required by state-machine transitions.
type Observer interface {
	DNSKEYEvidence(context.Context, string, ...model.Key) (time.Duration, error)
	AuthoritativeDNSKEYEvidence(context.Context, string, ...model.Key) (time.Duration, error)
	NoDSEvidence(context.Context, string) error
	DSEvidence(context.Context, string, []model.Key) error
	AuthoritativeDSEvidence(context.Context, string, []model.Key) (time.Duration, error)
	RRSIGBy(context.Context, string, model.Key) error
	AuthoritativeRRSIGBy(context.Context, string, model.Key) error
	DNSKEYRRSIGBy(context.Context, string, model.Key) error
	AuthoritativeDNSKEYRRSIGBy(context.Context, string, model.Key) error
	DelegationEvidence(context.Context, string, []string) error
}

// Probe collects DNSSEC evidence from recursive and authoritative paths.
type Probe struct {
	resolvers     []string
	authoritative []string
	local         string
	client        exchanger
}

type exchanger interface {
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

// New creates a DNSSEC probe backed by a TCP DNS client.
func New(resolvers, authoritative []string, local string, timeout time.Duration) *Probe {
	return &Probe{resolvers: append([]string(nil), resolvers...), authoritative: append([]string(nil), authoritative...), local: local, client: &dns.Client{Net: "tcp", Timeout: timeout}}
}

// NewWithClient creates a DNSSEC probe with a caller-provided exchange client.
func NewWithClient(resolvers, authoritative []string, local string, client exchanger) *Probe {
	return &Probe{resolvers: resolvers, authoritative: authoritative, local: local, client: client}
}

// DNSKEYEvidence verifies exact DNSKEY visibility on every configured path.
func (p *Probe) DNSKEYEvidence(ctx context.Context, zone string, keys ...model.Key) (time.Duration, error) {
	return p.dnskeyEvidence(ctx, zone, true, keys...)
}

// AuthoritativeDNSKEYEvidence verifies exact DNSKEY visibility without recursive validation.
func (p *Probe) AuthoritativeDNSKEYEvidence(ctx context.Context, zone string, keys ...model.Key) (time.Duration, error) {
	return p.dnskeyEvidence(ctx, zone, false, keys...)
}

func (p *Probe) dnskeyEvidence(ctx context.Context, zone string, includeResolvers bool, keys ...model.Key) (time.Duration, error) {
	name := dns.Fqdn(zone)
	expected, err := expectedDNSKEYs(name, keys)
	if err != nil {
		return 0, err
	}
	local, err := p.query(ctx, p.local, name, dns.TypeDNSKEY, false)
	if err != nil {
		return 0, fmt.Errorf("local authoritative DNSKEY: %w", err)
	}
	if err := verifyDNSKEYSet(local, expected, false, true, name); err != nil {
		return 0, fmt.Errorf("local authoritative DNSKEY: %w", err)
	}
	ttl := rrsetTTL(local.Answer, dns.TypeDNSKEY)
	for _, server := range p.authoritative {
		r, err := p.query(ctx, server, name, dns.TypeDNSKEY, false)
		if err != nil {
			return 0, fmt.Errorf("authoritative DNSKEY via %s: %w", server, err)
		}
		if err := verifyDNSKEYSet(r, expected, false, true, name); err != nil {
			return 0, fmt.Errorf("authoritative DNSKEY via %s: %w", server, err)
		}
		if observed := rrsetTTL(r.Answer, dns.TypeDNSKEY); observed > ttl {
			ttl = observed
		}
	}
	if includeResolvers {
		for _, resolver := range p.resolvers {
			r, err := p.query(ctx, resolver, name, dns.TypeDNSKEY, true)
			if err != nil {
				return 0, fmt.Errorf("recursive DNSKEY via %s: %w", resolver, err)
			}
			if err := verifyDNSKEYSet(r, expected, true, false, name); err != nil {
				return 0, fmt.Errorf("recursive DNSKEY via %s: %w", resolver, err)
			}
		}
	}
	if ttl == 0 {
		return 0, fmt.Errorf("authoritative DNSKEY TTL is zero")
	}
	return time.Duration(ttl) * time.Second, nil
}

// NoDSEvidence proves an initial insecure delegation without trusting an
// unauthenticated negative response. It validates the parent's NSEC/NSEC3
// denial with a parent DNSKEY RRset authenticated by each configured resolver,
// and independently requires the same proof from at least two parent servers.
func (p *Probe) NoDSEvidence(ctx context.Context, zone string) error {
	name := dns.Fqdn(zone)
	if len(p.resolvers) < 2 {
		return fmt.Errorf("at least two validating resolvers are required for no-DS evidence")
	}
	for _, resolver := range p.resolvers {
		r, err := p.query(ctx, resolver, name, dns.TypeDS, true)
		if err != nil {
			return fmt.Errorf("recursive no-DS via %s: %w", resolver, err)
		}
		if err := p.verifyNoDS(ctx, r, name, resolver, false); err != nil {
			return fmt.Errorf("recursive no-DS via %s: %w", resolver, err)
		}
	}
	servers := []string{"198.41.0.4:53", "[2001:503:ba3e::2:30]:53"}
	for depth := 0; depth < 12; depth++ {
		var referrals []string
		verified := 0
		var last error
		for _, server := range servers {
			r, err := p.query(ctx, server, name, dns.TypeDS, false)
			if err != nil {
				last = err
				continue
			}
			if hasType(r.Answer, dns.TypeDS) {
				return fmt.Errorf("authoritative parent already has DS for %s", name)
			}
			if hasType(r.Ns, dns.TypeSOA) {
				if err := p.verifyNoDS(ctx, r, name, p.resolvers[0], true); err != nil {
					last = fmt.Errorf("parent no-DS via %s: %w", server, err)
					continue
				}
				verified++
				continue
			}
			referrals = append(referrals, p.referralServers(ctx, r)...)
		}
		if verified >= 2 {
			return nil
		}
		if verified > 0 {
			return fmt.Errorf("only %d authoritative parent no-DS proof(s); need at least two", verified)
		}
		servers = unique(referrals)
		if len(servers) == 0 {
			if last != nil {
				return last
			}
			return fmt.Errorf("iterative no-DS lookup has no referral servers")
		}
	}
	return fmt.Errorf("iterative no-DS lookup exceeded referral depth")
}

// DelegationEvidence binds enrollment to the exact parent-side zone cut. It
// follows referrals iteratively and requires the complete expected NS RRset
// from at least two authoritative servers of the immediate parent.
func (p *Probe) DelegationEvidence(ctx context.Context, zone string, expected []string) error {
	name := dns.Fqdn(zone)
	want := make([]string, 0, len(expected))
	for _, item := range expected {
		want = append(want, strings.ToLower(dns.Fqdn(strings.TrimSpace(item))))
	}
	slices.Sort(want)
	want = slices.Compact(want)
	if len(want) < 2 {
		return fmt.Errorf("at least two expected delegated nameservers are required")
	}
	servers := []string{"198.41.0.4:53", "[2001:503:ba3e::2:30]:53"}
	for depth := 0; depth < 12; depth++ {
		verified := 0
		var referrals []string
		var last error
		for _, server := range servers {
			response, err := p.query(ctx, server, name, dns.TypeNS, false)
			if err != nil {
				last = err
				continue
			}
			got := delegatedNS(response, name)
			if len(got) > 0 {
				if !slices.Equal(got, want) {
					return fmt.Errorf("parent delegation via %s is %v, want %v", server, got, want)
				}
				verified++
				continue
			}
			referrals = append(referrals, p.referralServers(ctx, response)...)
		}
		if verified >= 2 {
			return nil
		}
		if verified > 0 {
			return fmt.Errorf("only %d exact parent delegation answer(s); need at least two", verified)
		}
		servers = unique(referrals)
		if len(servers) == 0 {
			if last != nil {
				return last
			}
			return fmt.Errorf("iterative delegation lookup has no referral servers")
		}
	}
	return fmt.Errorf("iterative delegation lookup exceeded referral depth")
}

func delegatedNS(response *dns.Msg, name string) []string {
	var out []string
	for _, section := range [][]dns.RR{response.Answer, response.Ns} {
		for _, rr := range section {
			ns, ok := rr.(*dns.NS)
			if ok && strings.EqualFold(dns.Fqdn(ns.Hdr.Name), name) {
				out = append(out, strings.ToLower(dns.Fqdn(ns.Ns)))
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func (p *Probe) verifyNoDS(ctx context.Context, response *dns.Msg, name, resolver string, requireAA bool) error {
	if requireAA && !response.Authoritative {
		return fmt.Errorf("response lacks authoritative-answer")
	}
	if hasType(response.Answer, dns.TypeDS) {
		return fmt.Errorf("DS is present")
	}
	parent := ""
	for _, rr := range response.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			parent = dns.Fqdn(soa.Hdr.Name)
			break
		}
	}
	if parent == "" || !dns.IsSubDomain(parent, name) || strings.EqualFold(parent, name) {
		return fmt.Errorf("negative DS response lacks a valid parent SOA")
	}
	keysResponse, err := p.query(ctx, resolver, parent, dns.TypeDNSKEY, true)
	if err != nil {
		return fmt.Errorf("parent DNSKEY: %w", err)
	}
	if !keysResponse.AuthenticatedData {
		return fmt.Errorf("parent DNSKEY response lacks authenticated-data")
	}
	var keys []*dns.DNSKEY
	for _, rr := range keysResponse.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			if !sameOwnerClass(key.Header(), parent) {
				return fmt.Errorf("parent DNSKEY owner/class mismatch")
			}
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return fmt.Errorf("parent DNSKEY RRset is empty")
	}
	return verifyNoDSProof(response, name, parent, keys, time.Now().UTC())
}

func verifyNoDSProof(response *dns.Msg, name, parent string, keys []*dns.DNSKEY, now time.Time) error {
	var nsec3s []*dns.NSEC3
	for _, rr := range response.Ns {
		switch n := rr.(type) {
		case *dns.NSEC:
			if strings.EqualFold(dns.Fqdn(n.Hdr.Name), dns.Fqdn(name)) && delegationWithoutDS(n.TypeBitMap) && validDenialSignature(response, n, parent, keys, now) {
				return nil
			}
		case *dns.NSEC3:
			nsec3s = append(nsec3s, n)
			if n.Match(name) && delegationWithoutDS(n.TypeBitMap) && validDenialSignature(response, n, parent, keys, now) {
				return nil
			}
		}
	}
	labels := dns.SplitDomainName(name)
	for i := 1; i < len(labels); i++ {
		closest := dns.Fqdn(strings.Join(labels[i:], "."))
		if !dns.IsSubDomain(parent, closest) {
			continue
		}
		for _, match := range nsec3s {
			if !match.Match(closest) || !validDenialSignature(response, match, parent, keys, now) {
				continue
			}
			nextCloser := dns.Fqdn(strings.Join(labels[i-1:], "."))
			for _, cover := range nsec3s {
				if cover.Flags&1 != 0 && sameNSEC3Parameters(match, cover) && cover.Cover(nextCloser) && validDenialSignature(response, cover, parent, keys, now) {
					return nil
				}
			}
			return fmt.Errorf("NSEC3 closest-encloser proof lacks a signed Opt-Out next-closer cover")
		}
	}
	return fmt.Errorf("no cryptographically valid NSEC/NSEC3 proof of DS absence")
}

func containsType(types []uint16, typ uint16) bool { return slices.Contains(types, typ) }

func delegationWithoutDS(types []uint16) bool {
	return containsType(types, dns.TypeNS) && !containsType(types, dns.TypeDS) && !containsType(types, dns.TypeSOA) && !containsType(types, dns.TypeCNAME)
}

func sameNSEC3Parameters(a, b *dns.NSEC3) bool {
	return a.Hash == b.Hash && a.Iterations == b.Iterations && strings.EqualFold(a.Salt, b.Salt)
}

func validDenialSignature(response *dns.Msg, rr dns.RR, parent string, keys []*dns.DNSKEY, now time.Time) bool {
	if !sameOwnerClass(rr.Header(), rr.Header().Name) || !dns.IsSubDomain(parent, rr.Header().Name) {
		return false
	}
	for _, candidate := range response.Ns {
		sig, ok := candidate.(*dns.RRSIG)
		if !ok || sig.TypeCovered != rr.Header().Rrtype || !strings.EqualFold(sig.Hdr.Name, rr.Header().Name) || !strings.EqualFold(sig.SignerName, parent) || !sig.ValidityPeriod(now) {
			continue
		}
		for _, key := range keys {
			if key.KeyTag() == sig.KeyTag && key.Algorithm == sig.Algorithm && sig.Verify(key, []dns.RR{rr}) == nil {
				return true
			}
		}
	}
	return false
}

// DSEvidence verifies exact DNSSEC-authenticated parent DS material through every resolver.
func (p *Probe) DSEvidence(ctx context.Context, zone string, keys []model.Key) error {
	name := dns.Fqdn(zone)
	want, err := expectedDS(name, keys)
	if err != nil {
		return err
	}
	for _, resolver := range p.resolvers {
		r, err := p.query(ctx, resolver, name, dns.TypeDS, true)
		if err != nil {
			return fmt.Errorf("recursive DS via %s: %w", resolver, err)
		}
		if !r.AuthenticatedData {
			return fmt.Errorf("recursive DS via %s lacks authenticated-data", resolver)
		}
		if err := exactDS(r, want, name, false); err != nil {
			return fmt.Errorf("recursive DS via %s: %w", resolver, err)
		}
	}
	return nil
}

// AuthoritativeDSEvidence verifies exact parent DS material and returns its maximum TTL.
func (p *Probe) AuthoritativeDSEvidence(ctx context.Context, zone string, keys []model.Key) (time.Duration, error) {
	name := dns.Fqdn(zone)
	want, err := expectedDS(name, keys)
	if err != nil {
		return 0, err
	}
	servers := []string{"198.41.0.4:53", "[2001:503:ba3e::2:30]:53"}
	for depth := 0; depth < 12; depth++ {
		var last error
		var referrals []string
		var maxTTL uint32
		authoritativeAnswers := 0
		for _, server := range servers {
			r, err := p.query(ctx, server, name, dns.TypeDS, false)
			if err != nil {
				last = err
				continue
			}
			if hasType(r.Answer, dns.TypeDS) {
				if err := exactDS(r, want, name, true); err != nil {
					last = fmt.Errorf("parent DS via %s: %w", server, err)
					continue
				}
				ttl := rrsetTTL(r.Answer, dns.TypeDS)
				if ttl > maxTTL {
					maxTTL = ttl
				}
				authoritativeAnswers++
				continue
			}
			next := p.referralServers(ctx, r)
			if len(next) > 0 {
				referrals = append(referrals, next...)
				continue
			}
			if hasType(r.Ns, dns.TypeSOA) {
				return 0, fmt.Errorf("authoritative parent has no DS for %s", name)
			}
		}
		if authoritativeAnswers >= 2 && maxTTL > 0 {
			return time.Duration(maxTTL) * time.Second, nil
		}
		if authoritativeAnswers > 0 {
			return 0, fmt.Errorf("only %d authoritative parent DS answer(s); need at least two", authoritativeAnswers)
		}
		if last != nil {
			return 0, last
		}
		servers = unique(referrals)
		if len(servers) == 0 {
			return 0, fmt.Errorf("iterative DS lookup has no referral servers")
		}
	}
	return 0, fmt.Errorf("iterative DS lookup exceeded referral depth")
}

// DNSKEYRRSIGBy verifies a DNSKEY RRset signature by the specified key on every path.
func (p *Probe) DNSKEYRRSIGBy(ctx context.Context, zone string, key model.Key) error {
	return p.verifySignatureEverywhere(ctx, dns.Fqdn(zone), dns.TypeDNSKEY, key)
}

// AuthoritativeDNSKEYRRSIGBy verifies a DNSKEY RRset signature on authoritative paths.
func (p *Probe) AuthoritativeDNSKEYRRSIGBy(ctx context.Context, zone string, key model.Key) error {
	return p.verifySignature(ctx, dns.Fqdn(zone), dns.TypeDNSKEY, key, false)
}

// RRSIGBy verifies a zone-data signature by the specified key on every path.
func (p *Probe) RRSIGBy(ctx context.Context, zone string, key model.Key) error {
	return p.verifySignatureEverywhere(ctx, dns.Fqdn(zone), dns.TypeSOA, key)
}

// AuthoritativeRRSIGBy verifies a zone-data signature on authoritative paths.
func (p *Probe) AuthoritativeRRSIGBy(ctx context.Context, zone string, key model.Key) error {
	return p.verifySignature(ctx, dns.Fqdn(zone), dns.TypeSOA, key, false)
}

func (p *Probe) verifySignatureEverywhere(ctx context.Context, name string, typ uint16, key model.Key) error {
	return p.verifySignature(ctx, name, typ, key, true)
}

func (p *Probe) verifySignature(ctx context.Context, name string, typ uint16, key model.Key, includeResolvers bool) error {
	rr, err := keyRR(name, key)
	if err != nil {
		return err
	}
	local, err := p.query(ctx, p.local, name, typ, false)
	if err != nil {
		return fmt.Errorf("local authoritative signature: %w", err)
	}
	if err := verifySignature(local, typ, rr, false, true, name, time.Now().UTC()); err != nil {
		return fmt.Errorf("local authoritative signature: %w", err)
	}
	for _, server := range p.authoritative {
		r, err := p.query(ctx, server, name, typ, false)
		if err != nil {
			return err
		}
		if err := verifySignature(r, typ, rr, false, true, name, time.Now().UTC()); err != nil {
			return fmt.Errorf("authoritative signature via %s: %w", server, err)
		}
	}
	if includeResolvers {
		for _, resolver := range p.resolvers {
			r, err := p.query(ctx, resolver, name, typ, true)
			if err != nil {
				return err
			}
			if err := verifySignature(r, typ, rr, true, false, name, time.Now().UTC()); err != nil {
				return fmt.Errorf("recursive signature via %s: %w", resolver, err)
			}
		}
	}
	return nil
}

func (p *Probe) query(ctx context.Context, server, name string, typ uint16, recursive bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, typ)
	m.RecursionDesired = recursive
	m.AuthenticatedData = recursive
	m.SetEdns0(1232, true)
	var r *dns.Msg
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		r, _, err = p.client.ExchangeContext(ctx, m, server)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("rcode %s", dns.RcodeToString[r.Rcode])
	}
	return r, nil
}

func (p *Probe) referralServers(ctx context.Context, r *dns.Msg) []string {
	names := map[string]bool{}
	for _, rr := range r.Ns {
		if n, ok := rr.(*dns.NS); ok {
			owner := strings.ToLower(dns.Fqdn(n.Hdr.Name))
			target := strings.ToLower(dns.Fqdn(n.Ns))
			names[target] = dns.IsSubDomain(owner, target)
		}
	}
	var out []string
	for _, rr := range r.Extra {
		switch x := rr.(type) {
		case *dns.A:
			if names[strings.ToLower(x.Hdr.Name)] {
				out = append(out, net.JoinHostPort(x.A.String(), "53"))
			}
		case *dns.AAAA:
			if names[strings.ToLower(x.Hdr.Name)] {
				out = append(out, net.JoinHostPort(x.AAAA.String(), "53"))
			}
		}
	}
	if len(out) > 0 {
		return unique(out)
	}
	for name := range names {
		for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
			resp, err := p.query(ctx, p.resolvers[0], name, typ, true)
			if err != nil {
				continue
			}
			for _, rr := range resp.Answer {
				switch x := rr.(type) {
				case *dns.A:
					out = append(out, net.JoinHostPort(x.A.String(), "53"))
				case *dns.AAAA:
					out = append(out, net.JoinHostPort(x.AAAA.String(), "53"))
				}
			}
		}
	}
	return unique(out)
}

// DNSSECDataForKey converts a validated PowerDNS key into registrar public material.
func DNSSECDataForKey(zone string, key model.Key) (model.DNSSECData, error) {
	rr, err := keyRR(dns.Fqdn(zone), key)
	if err != nil {
		return model.DNSSECData{}, err
	}
	return model.DNSSECData{Flags: rr.Flags, Protocol: rr.Protocol, Algorithm: rr.Algorithm, PublicKey: rr.PublicKey}, nil
}
func expectedDNSKEYs(zone string, keys []model.Key) ([]*dns.DNSKEY, error) {
	out := make([]*dns.DNSKEY, 0, len(keys))
	for _, key := range keys {
		rr, err := keyRR(zone, key)
		if err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	return out, nil
}
func keyRR(zone string, key model.Key) (*dns.DNSKEY, error) {
	content := strings.TrimSpace(key.DNSKEY)
	parts := strings.Fields(content)
	if len(parts) > 4 && strings.EqualFold(parts[len(parts)-5], "DNSKEY") {
		content = strings.Join(parts[len(parts)-4:], " ")
	}
	rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN DNSKEY %s", dns.Fqdn(zone), content))
	if err != nil {
		return nil, fmt.Errorf("parse public DNSKEY for key %d: %w", key.ID, err)
	}
	k, ok := rr.(*dns.DNSKEY)
	if !ok {
		return nil, fmt.Errorf("key %d is not DNSKEY", key.ID)
	}
	return k, nil
}
func expectedDS(zone string, keys []model.Key) ([]string, error) {
	var out []string
	for _, key := range keys {
		rr, err := keyRR(zone, key)
		if err != nil {
			return nil, err
		}
		ds := rr.ToDS(dns.SHA256)
		if ds == nil {
			return nil, fmt.Errorf("cannot derive SHA-256 DS for key %d", key.ID)
		}
		out = append(out, dsKey(ds))
	}
	slices.Sort(out)
	return out, nil
}
func verifyDNSKEYSet(r *dns.Msg, want []*dns.DNSKEY, requireAD, requireAA bool, owner string) error {
	if requireAD && !r.AuthenticatedData {
		return fmt.Errorf("response lacks authenticated-data")
	}
	if requireAA && !r.Authoritative {
		return fmt.Errorf("response lacks authoritative-answer")
	}
	var got []string
	for _, a := range r.Answer {
		if k, ok := a.(*dns.DNSKEY); ok {
			if !sameOwnerClass(k.Header(), owner) {
				return fmt.Errorf("DNSKEY owner/class mismatch")
			}
			got = append(got, dnskeyKey(k))
		}
	}
	var expected []string
	for _, k := range want {
		expected = append(expected, dnskeyKey(k))
	}
	slices.Sort(got)
	slices.Sort(expected)
	if !slices.Equal(got, expected) {
		return fmt.Errorf("DNSKEY set mismatch: got %v expected %v", got, expected)
	}
	return nil
}
func verifySignature(r *dns.Msg, typ uint16, key *dns.DNSKEY, requireAD, requireAA bool, owner string, now time.Time) error {
	if requireAD && !r.AuthenticatedData {
		return fmt.Errorf("response lacks authenticated-data")
	}
	if requireAA && !r.Authoritative {
		return fmt.Errorf("response lacks authoritative-answer")
	}
	var rrset []dns.RR
	var sigs []*dns.RRSIG
	for _, a := range r.Answer {
		if a.Header().Rrtype == typ {
			if !sameOwnerClass(a.Header(), owner) {
				return fmt.Errorf("covered RRset owner/class mismatch")
			}
			rrset = append(rrset, a)
		}
		if s, ok := a.(*dns.RRSIG); ok && s.TypeCovered == typ && s.KeyTag == key.KeyTag() && s.Algorithm == key.Algorithm {
			sigs = append(sigs, s)
		}
	}
	if len(rrset) == 0 {
		return fmt.Errorf("covered RRset is absent")
	}
	for _, sig := range sigs {
		if !sameOwnerClass(sig.Header(), owner) || !sig.ValidityPeriod(now) {
			continue
		}
		if err := sig.Verify(key, rrset); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no cryptographically valid RRSIG by expected DNSKEY")
}
func exactDS(r *dns.Msg, want []string, owner string, requireAA bool) error {
	if requireAA && !r.Authoritative {
		return fmt.Errorf("response lacks authoritative-answer")
	}
	var got []string
	for _, a := range r.Answer {
		if ds, ok := a.(*dns.DS); ok {
			if !sameOwnerClass(ds.Header(), owner) {
				return fmt.Errorf("DS owner/class mismatch")
			}
			got = append(got, dsKey(ds))
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		return fmt.Errorf("DS set mismatch: got %v expected %v", got, want)
	}
	return nil
}

func sameOwnerClass(h *dns.RR_Header, owner string) bool {
	return h.Class == dns.ClassINET && strings.EqualFold(dns.Fqdn(h.Name), dns.Fqdn(owner))
}
func dnskeyKey(k *dns.DNSKEY) string {
	return fmt.Sprintf("%d/%d/%d/%s", k.Flags, k.Protocol, k.Algorithm, k.PublicKey)
}
func dsKey(ds *dns.DS) string {
	return fmt.Sprintf("%d/%d/%d/%s", ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest))
}
func rrsetTTL(rrs []dns.RR, typ uint16) uint32 {
	var ttl uint32
	for _, rr := range rrs {
		if rr.Header().Rrtype == typ && (ttl == 0 || rr.Header().Ttl > ttl) {
			ttl = rr.Header().Ttl
		}
	}
	return ttl
}
func hasType(rrs []dns.RR, typ uint16) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == typ {
			return true
		}
	}
	return false
}
func unique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, x := range in {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
