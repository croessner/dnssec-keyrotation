package dnsprobe

import (
	"context"
	"crypto"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dnssec-keyrotation/internal/model"
	"github.com/miekg/dns"
)

type retryExchange struct{ attempts int }

func (f *retryExchange) ExchangeContext(_ context.Context, request *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
	f.attempts++
	if f.attempts < 3 {
		return nil, 0, errors.New("temporary EOF")
	}
	response := new(dns.Msg)
	response.SetReply(request)
	return response, 0, nil
}

func TestQueryRetriesTransientTransportFailure(t *testing.T) {
	ex := &retryExchange{}
	p := NewWithClient(nil, nil, "local:53", ex)
	if _, err := p.query(context.Background(), "resolver:53", "example.test.", dns.TypeDS, true); err != nil {
		t.Fatal(err)
	}
	if ex.attempts != 3 {
		t.Fatalf("attempts=%d want=3", ex.attempts)
	}
}

func TestDelegatedNSExtractsOnlyExactChildZoneCut(t *testing.T) {
	response := new(dns.Msg)
	response.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns2.example.net."},
		&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns1.example.net."},
		&dns.NS{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ignored.example."},
	}
	got := delegatedNS(response, "example.test.")
	want := []string{"ns1.example.net.", "ns2.example.net."}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("delegation=%v want=%v", got, want)
	}
}

type localSignatureExchange struct {
	local string
	valid *dns.Msg
	soa   dns.RR
}

func (f localSignatureExchange) ExchangeContext(_ context.Context, request *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	if server == f.local {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		response.Answer = []dns.RR{f.soa}
		return response, 0, nil
	}
	return f.valid.Copy(), 0, nil
}

func TestAuthoritativeSignatureRejectsInvalidLocalDespiteValidExternal(t *testing.T) {
	now := time.Now().UTC()
	owner := "example.test."
	key, signer := denialTestKey(t, owner)
	soa, err := dns.NewRR(owner + " 300 IN SOA ns.example.test. hostmaster.example.test. 1 3600 600 86400 300")
	if err != nil {
		t.Fatal(err)
	}
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300}, TypeCovered: dns.TypeSOA, Algorithm: key.Algorithm, Labels: uint8(dns.CountLabel(owner)), OrigTtl: 300, Expiration: uint32(now.Add(time.Hour).Unix()), Inception: uint32(now.Add(-time.Hour).Unix()), KeyTag: key.KeyTag(), SignerName: owner}
	if err := sig.Sign(signer, []dns.RR{soa}); err != nil {
		t.Fatal(err)
	}
	valid := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}, Answer: []dns.RR{soa, sig}}
	content := strings.Join(strings.Fields(key.String())[4:], " ")
	p := NewWithClient(nil, []string{"auth1:53", "auth2:53"}, "local:53", localSignatureExchange{local: "local:53", valid: valid, soa: soa})
	if err := p.AuthoritativeRRSIGBy(context.Background(), owner, model.Key{ID: 1, DNSKEY: content}); err == nil {
		t.Fatal("invalid local signature was accepted because external authorities were valid")
	}
}

func TestDNSSECDataForKeyParsesPowerDNSContent(t *testing.T) {
	k := model.Key{ID: 7, DNSKEY: "257 3 13 AQID"}
	d, err := DNSSECDataForKey("example.test.", k)
	if err != nil {
		t.Fatal(err)
	}
	if d.Flags != 257 || d.Protocol != 3 || d.Algorithm != 13 || d.PublicKey != "AQID" {
		t.Fatalf("unexpected data: %+v", d)
	}
}

func TestVerifySignatureRejectsExpiredRRSIG(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	owner := "example.test."
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 256, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	private, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	soa, err := dns.NewRR(owner + " 300 IN SOA ns.example.test. hostmaster.example.test. 1 3600 600 86400 300")
	if err != nil {
		t.Fatal(err)
	}
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300}, TypeCovered: dns.TypeSOA, Algorithm: key.Algorithm, Labels: uint8(dns.CountLabel(owner)), OrigTtl: 300, Expiration: uint32(now.Add(-time.Hour).Unix()), Inception: uint32(now.Add(-2 * time.Hour).Unix()), KeyTag: key.KeyTag(), SignerName: owner}
	signer, ok := private.(crypto.Signer)
	if !ok {
		t.Fatal("generated DNSSEC key is not a crypto.Signer")
	}
	if err := sig.Sign(signer, []dns.RR{soa}); err != nil {
		t.Fatal(err)
	}
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}, Answer: []dns.RR{soa, sig}}
	if err := verifySignature(msg, dns.TypeSOA, key, false, true, owner, now); err == nil {
		t.Fatal("expired signature accepted")
	}
}

func TestDNSKEYEvidenceUsesMaximumAuthoritativeTTL(t *testing.T) {
	owner := "example.test."
	key := model.Key{ID: 1, DNSKEY: "257 3 13 AQID"}
	servers := []string{"local:53", "auth1:53", "auth2:53", "resolver1:53", "resolver2:53"}
	p := NewWithClient([]string{servers[3], servers[4]}, []string{servers[1], servers[2]}, servers[0], fakeDNSKEYExchange{owner: owner, content: key.DNSKEY, ttls: map[string]uint32{servers[0]: 3600, servers[1]: 86400, servers[2]: 259200, servers[3]: 7200, servers[4]: 7200}})
	got, err := p.DNSKEYEvidence(context.Background(), owner, key)
	if err != nil {
		t.Fatal(err)
	}
	if got != 72*time.Hour {
		t.Fatalf("ttl=%s want=72h", got)
	}
}

func TestVerifyDNSKEYSetRejectsUnexpectedPublishedKey(t *testing.T) {
	owner := "example.test."
	wanted, err := dns.NewRR(owner + " 300 IN DNSKEY 257 3 13 AQID")
	if err != nil {
		t.Fatal(err)
	}
	extra, err := dns.NewRR(owner + " 300 IN DNSKEY 256 3 13 BAUG")
	if err != nil {
		t.Fatal(err)
	}
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}, Answer: []dns.RR{wanted, extra}}
	if err := verifyDNSKEYSet(msg, []*dns.DNSKEY{wanted.(*dns.DNSKEY)}, false, true, owner); err == nil {
		t.Fatal("unexpected DNSKEY was accepted")
	}
}

func TestVerifyNoDSProofAcceptsSignedNSECDelegation(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	key, signer := denialTestKey(t, "test.")
	nsec := &dns.NSEC{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300}, NextDomain: "next.test.", TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG}}
	msg := &dns.Msg{Ns: []dns.RR{nsec, signDenial(t, signer, key, nsec, now)}}
	if err := verifyNoDSProof(msg, "example.test.", "test.", []*dns.DNSKEY{key}, now); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyNoDSProofRejectsDelegationWithCNAME(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	key, signer := denialTestKey(t, "test.")
	nsec := &dns.NSEC{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300}, NextDomain: "next.test.", TypeBitMap: []uint16{dns.TypeNS, dns.TypeCNAME, dns.TypeRRSIG}}
	msg := &dns.Msg{Ns: []dns.RR{nsec, signDenial(t, signer, key, nsec, now)}}
	if err := verifyNoDSProof(msg, "example.test.", "test.", []*dns.DNSKEY{key}, now); err == nil {
		t.Fatal("CNAME-bearing denial was accepted")
	}
}

func TestVerifyNoDSProofRequiresCompleteSignedNSEC3OptOutChain(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	parent, name := "test.", "example.test."
	key, signer := denialTestKey(t, parent)
	parentHash := dns.HashName(parent, dns.SHA1, 0, "")
	closest := &dns.NSEC3{Hdr: dns.RR_Header{Name: parentHash + "." + parent, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300}, Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "", HashLength: 20, NextDomain: "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG}}
	cover := &dns.NSEC3{Hdr: dns.RR_Header{Name: "00000000000000000000000000000000." + parent, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300}, Hash: dns.SHA1, Flags: 1, Iterations: 0, Salt: "", HashLength: 20, NextDomain: "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG}}
	if !closest.Match(parent) || !cover.Cover(name) {
		t.Fatal("invalid NSEC3 test fixture")
	}
	closestSig := signDenial(t, signer, key, closest, now)
	coverSig := signDenial(t, signer, key, cover, now)
	complete := &dns.Msg{Ns: []dns.RR{closest, closestSig, cover, coverSig}}
	if err := verifyNoDSProof(complete, name, parent, []*dns.DNSKEY{key}, now); err != nil {
		t.Fatal(err)
	}
	incomplete := &dns.Msg{Ns: []dns.RR{cover, coverSig}}
	if err := verifyNoDSProof(incomplete, name, parent, []*dns.DNSKEY{key}, now); err == nil {
		t.Fatal("incomplete Opt-Out closest-encloser proof was accepted")
	}
}

func denialTestKey(t *testing.T, parent string) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: parent, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	private, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		t.Fatal("generated DNSSEC key is not a signer")
	}
	return key, signer
}

func signDenial(t *testing.T, signer crypto.Signer, key *dns.DNSKEY, rr dns.RR, now time.Time) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: rr.Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: rr.Header().Ttl}, TypeCovered: rr.Header().Rrtype, Algorithm: key.Algorithm, Labels: uint8(dns.CountLabel(rr.Header().Name)), OrigTtl: rr.Header().Ttl, Expiration: uint32(now.Add(time.Hour).Unix()), Inception: uint32(now.Add(-time.Hour).Unix()), KeyTag: key.KeyTag(), SignerName: key.Hdr.Name}
	if err := sig.Sign(signer, []dns.RR{rr}); err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestExactDSRejectsNonAuthoritativeOrWrongOwner(t *testing.T) {
	ds, err := dns.NewRR("other.test. 300 IN DS 12345 13 2 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	msg := &dns.Msg{Answer: []dns.RR{ds}}
	want := []string{"12345/13/2/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	if err := exactDS(msg, want, "example.test.", true); err == nil {
		t.Fatal("non-authoritative wrong-owner DS accepted")
	}
}

type fakeDNSKEYExchange struct {
	owner   string
	content string
	ttls    map[string]uint32
}

func (f fakeDNSKEYExchange) ExchangeContext(_ context.Context, request *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	rr, err := dns.NewRR(f.owner + " 300 IN DNSKEY " + f.content)
	if err != nil {
		return nil, 0, err
	}
	rr.Header().Ttl = f.ttls[server]
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	response.AuthenticatedData = true
	response.Answer = []dns.RR{rr}
	return response, 0, nil
}
