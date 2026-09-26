package shaken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testPKI struct {
	rootCert *x509.Certificate
	rootPEM  []byte
	leafKey  *ecdsa.PrivateKey
	leafCert *x509.Certificate
	chainPEM []byte
}

// newPKI builds a root and a leaf carrying a TNAuthList with the given SPC,
// encoded with the explicit tag RFC 8226 specifies.
func newPKI(t *testing.T, spc string) *testPKI {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test STI-CA Root", Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	inner, _ := asn1.MarshalWithParams(spc, "ia5")
	entry := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}
	entryDER, _ := asn1.Marshal(entry)
	seq := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: entryDER}
	tnAuth, _ := asn1.Marshal(seq)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber:    big.NewInt(4242),
		Subject:         pkix.Name{CommonName: "SHAKEN " + spc, Organization: []string{"Example Carrier LLC"}},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(12 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: oidTNAuthList, Critical: false, Value: tnAuth}},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	return &testPKI{rootCert: rootCert, rootPEM: rootPEM, leafKey: leafKey, leafCert: leafCert, chainPEM: append(leafPEM, rootPEM...)}
}

func (p *testPKI) passport(t *testing.T, x5u, attest, orig, dest string, iat int64) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "ppt": "shaken", "typ": "passport", "x5u": x5u})
	body, _ := json.Marshal(map[string]any{
		"attest": attest, "origid": "00000000-0000-0000-0000-000000000001", "iat": iat,
		"orig": map[string]string{"tn": orig}, "dest": map[string][]string{"tn": {dest}},
	})
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, p.leafKey, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + enc.EncodeToString(sig) + ";info=<" + x5u + ">;alg=ES256;ppt=shaken"
}

func trustWithRoot(p *testPKI) *TrustStore {
	ts := NewTrustStore("", "", "")
	pool := x509.NewCertPool()
	pool.AddCert(p.rootCert)
	ts.roots, ts.rootCount = pool, 1
	return ts
}

func newVerifier(trust *TrustStore) *Verifier {
	opts := DefaultOptions()
	opts.AllowHTTP = true
	opts.Budget = 2 * time.Second
	return New(trust, opts)
}

func TestVerifyPassesAndReadsSPC(t *testing.T) {
	p := newPKI(t, "1234")
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(p.chainPEM)
	}))
	defer srv.Close()
	x5u := srv.URL + "/cert.pem"

	v := newVerifier(trustWithRoot(p))
	id := p.passport(t, x5u, "A", "14155550100", "15551212", time.Now().Unix())
	r := v.Verify(context.Background(), id, "+14155550100", "+15551212")
	if r.Verstat != VerstatPassed {
		t.Fatalf("verstat %s errors %v", r.Verstat, r.Errors)
	}
	if !r.Signature || !r.Chain || !r.CertValid || !r.Fresh || !r.OrigMatch || !r.DestMatch || r.Revoked {
		t.Fatalf("flags: %+v", r)
	}
	if r.Signer.SPC != "1234" || r.Signer.Org != "Example Carrier LLC" || r.Signer.CN != "SHAKEN 1234" {
		t.Fatalf("signer: %+v", r.Signer)
	}
	if r.Attest != "A" || r.OrigTN != "14155550100" || r.Cached {
		t.Fatalf("claims: %+v", r)
	}

	// Second call hits the cache. One HTTP fetch total.
	r2 := v.Verify(context.Background(), id, "+14155550100", "+15551212")
	if !r2.Cached || r2.Verstat != VerstatPassed || atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("cache: cached=%v hits=%d", r2.Cached, hits)
	}
}

// Describe names the signer from the certificate a switch signs with and
// never claims a signature was checked.
func TestDescribeReadsTheSwitchCertificate(t *testing.T) {
	p := newPKI(t, "1234")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(p.chainPEM) }))
	defer srv.Close()

	r := newVerifier(trustWithRoot(p)).Describe(context.Background(), "b", "o-1", srv.URL+"/cert.pem")
	if r.Source != SourceSwitch || r.Attest != "B" || r.OrigID != "o-1" || r.Verstat != "" || r.Signature || r.Present {
		t.Fatalf("claim: %+v", r)
	}
	if r.Signer.SPC != "1234" || r.Signer.Org != "Example Carrier LLC" || !r.Chain || !r.CertValid || r.Revoked {
		t.Fatalf("certificate: %+v", r)
	}

	var off *Verifier
	if r := off.Describe(context.Background(), "A", "", srv.URL+"/cert.pem"); r.Source != SourceSwitch || r.Attest != "A" || r.Signer.SPC != "" {
		t.Fatalf("nil verifier: %+v", r)
	}
}

func TestVerifyFailsOnTamperedPayload(t *testing.T) {
	p := newPKI(t, "1234")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(p.chainPEM) }))
	defer srv.Close()
	v := newVerifier(trustWithRoot(p))
	id := p.passport(t, srv.URL, "A", "14155550100", "15551212", time.Now().Unix())
	parts := strings.SplitN(id, ".", 3)
	body, _ := json.Marshal(map[string]any{"attest": "A", "iat": time.Now().Unix(), "orig": map[string]string{"tn": "19999999999"}})
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(body) + "." + parts[2]
	r := v.Verify(context.Background(), tampered, "+19999999999", "")
	if r.Verstat != VerstatFailed || r.Signature {
		t.Fatalf("tampered passport must fail: %+v", r)
	}
}

func TestVerifyFailsOnUntrustedRootAndOrigMismatchAndStale(t *testing.T) {
	p := newPKI(t, "1234")
	other := newPKI(t, "9999")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(p.chainPEM) }))
	defer srv.Close()

	v := newVerifier(trustWithRoot(other))
	id := p.passport(t, srv.URL, "B", "14155550100", "15551212", time.Now().Unix()-600)
	r := v.Verify(context.Background(), id, "+14155550199", "+15551212")
	if r.Verstat != VerstatFailed {
		t.Fatalf("verstat %s", r.Verstat)
	}
	if r.Chain || r.Fresh || r.OrigMatch || !r.Signature {
		t.Fatalf("flags: chain=%v fresh=%v orig=%v sig=%v", r.Chain, r.Fresh, r.OrigMatch, r.Signature)
	}
	joined := strings.Join(r.Errors, " | ")
	for _, want := range []string{"chain:", "iat is", "orig tn does not match"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("errors missing %q: %s", want, joined)
		}
	}
}

func TestVerifyRevokedSerial(t *testing.T) {
	p := newPKI(t, "1234")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(p.chainPEM) }))
	defer srv.Close()
	ts := trustWithRoot(p)
	ts.revoked[p.leafCert.SerialNumber.Text(16)] = struct{}{}
	v := newVerifier(ts)
	id := p.passport(t, srv.URL, "A", "14155550100", "15551212", time.Now().Unix())
	r := v.Verify(context.Background(), id, "", "")
	if r.Verstat != VerstatFailed || !r.Revoked {
		t.Fatalf("revoked leaf must fail: %+v", r)
	}
}

func TestColdCacheRespectsBudgetThenWarms(t *testing.T) {
	p := newPKI(t, "1234")
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		_, _ = w.Write(p.chainPEM)
	}))
	defer srv.Close()
	opts := DefaultOptions()
	opts.AllowHTTP = true
	opts.Budget = 50 * time.Millisecond
	v := New(trustWithRoot(p), opts)
	id := p.passport(t, srv.URL, "A", "14155550100", "15551212", time.Now().Unix())

	start := time.Now()
	r := v.Verify(context.Background(), id, "", "")
	if !r.Pending || r.Verstat != VerstatNone {
		t.Fatalf("cold cache must return pending: %+v", r)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("budget not honoured: %v", time.Since(start))
	}
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r = v.Verify(context.Background(), id, "", "")
		if r.Verstat == VerstatPassed {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("cache never warmed: %+v", r)
}

func TestNoIdentityAndBadHeader(t *testing.T) {
	v := newVerifier(nil)
	if r := v.Verify(context.Background(), "", "", ""); r.Present || r.Verstat != VerstatNone {
		t.Fatalf("empty: %+v", r)
	}
	r := v.Verify(context.Background(), "not.a.jwt;info=<https://x>", "", "")
	if !r.Present || r.ParsedJWT || r.Verstat != VerstatNone {
		t.Fatalf("garbage: %+v", r)
	}
	r = v.Verify(context.Background(), "eyJhbGciOiJSUzI1NiIsIng1dSI6Imh0dHBzOi8veCJ9.e30.AA", "", "")
	if r.Verstat != VerstatFailed || !strings.Contains(strings.Join(r.Errors, " "), "ES256 required") {
		t.Fatalf("alg: %+v", r)
	}
}

func TestParseCAListEnvelopeJWS(t *testing.T) {
	p := newPKI(t, "1")
	payload, _ := json.Marshal(map[string]any{"version": "1.0", "sequence": 1518, "trustList": []string{string(p.rootPEM)}})
	jws := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".AA"
	env, _ := json.Marshal(map[string]string{"status": "success", "caList": jws})
	certs, seq, err := ParseCAList(env)
	if err != nil || len(certs) != 1 || seq != 1518 {
		t.Fatalf("envelope: %d %d %v", len(certs), seq, err)
	}
	certs, _, err = ParseCAList(p.rootPEM)
	if err != nil || len(certs) != 1 {
		t.Fatalf("pem: %d %v", len(certs), err)
	}
	if _, _, err := ParseCAList([]byte("nothing here")); err == nil {
		t.Fatal("garbage must error")
	}
}

func TestSPCImplicitEncoding(t *testing.T) {
	// Some CAs encode the [0] as a primitive with the string bytes inline.
	entry := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: false, Bytes: []byte("7777")}
	entryDER, _ := asn1.Marshal(entry)
	seq := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: entryDER}
	tnAuth, _ := asn1.Marshal(seq)
	cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: oidTNAuthList, Value: tnAuth}}}
	if got := spcFromCert(cert); got != "7777" {
		t.Fatalf("spc %q", got)
	}
}
