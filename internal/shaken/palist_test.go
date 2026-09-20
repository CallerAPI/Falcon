package shaken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type paRig struct {
	srv     *httptest.Server
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	certPEM []byte
	list    string
}

func newPARig(t *testing.T, subject string, seq int64, exp int64) *paRig {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: subject, Organization: []string{subject}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	r := &paRig{key: key, cert: cert, certPEM: certPEM}

	// One root in the list: any self-signed cert will do.
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test STI-CA Root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))

	mux := http.NewServeMux()
	mux.HandleFunc("/pa.crt", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(r.certPEM) })
	mux.HandleFunc("/ca-list", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "caList": r.list})
	})
	r.srv = httptest.NewTLSServer(mux)
	t.Cleanup(r.srv.Close)

	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "x5u": r.srv.URL + "/pa.crt"})
	payload, _ := json.Marshal(map[string]any{"version": "1.0", "sequence": seq, "exp": exp, "trustList": []string{rootPEM}})
	r.list = r.sign(base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload))
	return r
}

func (r *paRig) sign(signingInput string) string {
	digest := sha256.Sum256([]byte(signingInput))
	rr, ss, _ := ecdsa.Sign(rand.Reader, r.key, digest[:])
	sig := make([]byte, 64)
	rr.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (r *paRig) store() *TrustStore {
	ts := NewTrustStore(r.srv.URL+"/ca-list", "", "")
	ts.HTTP = r.srv.Client()
	return ts
}

func TestSignedListAcceptedAndRoots(t *testing.T) {
	rig := newPARig(t, "STI-PA CA List", 1518, time.Now().Add(time.Hour).Unix())
	ts := rig.store()
	ts.LoadRoots(context.Background())
	st := ts.Status()
	if st.Roots != 1 || st.Sequence != 1518 || st.RootsError != "" {
		t.Fatalf("status: %+v", st)
	}
}

func TestSignedListRejectsTamperExpiryRollbackOriginAndPin(t *testing.T) {
	rig := newPARig(t, "STI-PA CA List", 1518, time.Now().Add(time.Hour).Unix())
	ts := rig.store()
	ctx := context.Background()

	// Tampered payload: same header and signature, one changed character.
	parts := strings.Split(rig.list, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	tampered := strings.Replace(string(payload), `"sequence":1518`, `"sequence":1519`, 1)
	bad := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(tampered)) + "." + parts[2]
	if _, _, err := ts.verifySignedList(ctx, bad, ts.CAURL, 0); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("tampered list: %v", err)
	}

	// Good list, then a rollback.
	if _, seq, err := ts.verifySignedList(ctx, rig.list, ts.CAURL, 0); err != nil || seq != 1518 {
		t.Fatalf("good list: %v seq=%d", err, seq)
	}
	if _, _, err := ts.verifySignedList(ctx, rig.list, ts.CAURL, 1600); err == nil || !strings.Contains(err.Error(), "sequence lower") {
		t.Fatalf("rollback: %v", err)
	}

	// Expired.
	exp := newPARig(t, "STI-PA CA List", 1518, time.Now().Add(-time.Minute).Unix())
	if _, _, err := exp.store().verifySignedList(ctx, exp.list, exp.srv.URL+"/ca-list", 0); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: %v", err)
	}

	// x5u on a different host than the list.
	if _, _, err := ts.verifySignedList(ctx, rig.list, "https://other.example/ca-list", 0); err == nil || !strings.Contains(err.Error(), "differs from list host") {
		t.Fatalf("origin: %v", err)
	}

	// Signer that does not name the STI-PA.
	imp := newPARig(t, "Some Random CA", 1, time.Now().Add(time.Hour).Unix())
	if _, _, err := imp.store().verifySignedList(ctx, imp.list, imp.srv.URL+"/ca-list", 0); err == nil || !strings.Contains(err.Error(), "name the STI-PA") {
		t.Fatalf("impostor: %v", err)
	}

	// Pin mismatch, then pin match.
	ts.ListPolicy.PinSPKI = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, _, err := ts.verifySignedList(ctx, rig.list, ts.CAURL, 0); err == nil || !strings.Contains(err.Error(), "PA_PIN") {
		t.Fatalf("pin mismatch: %v", err)
	}
	sum := sha256.Sum256(rig.cert.RawSubjectPublicKeyInfo)
	ts.ListPolicy.PinSPKI = base64.StdEncoding.EncodeToString(sum[:])
	if _, _, err := ts.verifySignedList(ctx, rig.list, ts.CAURL, 0); err != nil {
		t.Fatalf("pin match: %v", err)
	}
}

func TestFailedRefreshKeepsLastGoodList(t *testing.T) {
	rig := newPARig(t, "STI-PA CA List", 10, time.Now().Add(time.Hour).Unix())
	ts := rig.store()
	ctx := context.Background()
	ts.LoadRoots(ctx)
	if ts.Status().Roots != 1 {
		t.Fatal("first load failed")
	}
	// Serve a rolled-back list next.
	rig2 := newPARig(t, "STI-PA CA List", 5, time.Now().Add(time.Hour).Unix())
	rig.list = rig2.list
	ts.LoadRoots(ctx)
	st := ts.Status()
	if st.Roots != 1 || st.Sequence != 10 || st.RootsError == "" {
		t.Fatalf("after bad refresh: %+v", st)
	}
}
