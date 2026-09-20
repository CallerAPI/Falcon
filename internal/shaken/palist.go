package shaken

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ListPolicy says how the signed STI-PA CA list is checked. Zero value
// verifies the JWS signature with the certificate the list names, requires
// that certificate to come from the same host as the list, rejects an
// expired list, and refuses a sequence number lower than the last accepted.
// A pin or a root file tightens it to a specific STI-PA key.
type ListPolicy struct {
	// Verify turns the whole check off when false. Lab use only.
	Verify bool
	// PinSPKI is the base64 SHA-256 of the list-signing certificate's
	// SubjectPublicKeyInfo. When set, the certificate must match.
	PinSPKI string
	// Roots, when non-empty, is the STI-PA root the signing certificate
	// must chain to.
	Roots *x509.CertPool
}

// listSigner caches the STI-PA list-signing certificate by URL.
type listSigner struct {
	mu   sync.Mutex
	url  string
	cert *x509.Certificate
	at   time.Time
}

var errListRollback = errors.New("sequence lower than the last accepted list")

// verifySignedList checks the caList JWS and returns its payload. listURL is
// where the list came from; the signing certificate must live on the same
// host. lastSeq is the last accepted sequence.
func (t *TrustStore) verifySignedList(ctx context.Context, jws string, listURL string, lastSeq int64) ([]byte, int64, error) {
	parts := strings.Split(strings.TrimSpace(jws), ".")
	if len(parts) != 3 {
		return nil, 0, errors.New("caList is not a JWS")
	}
	headerRaw, err := b64(parts[0])
	if err != nil {
		return nil, 0, err
	}
	var header struct {
		Alg string `json:"alg"`
		X5U string `json:"x5u"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, 0, fmt.Errorf("caList header: %w", err)
	}
	payload, err := b64(parts[1])
	if err != nil {
		return nil, 0, err
	}
	var body struct {
		Sequence int64 `json:"sequence"`
		Exp      int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, 0, fmt.Errorf("caList payload: %w", err)
	}

	if !t.ListPolicy.Verify {
		return payload, body.Sequence, nil
	}
	if header.Alg != "ES256" {
		return nil, 0, fmt.Errorf("caList alg %q, want ES256", header.Alg)
	}
	if err := sameOrigin(header.X5U, listURL); err != nil {
		return nil, 0, err
	}
	cert, err := t.listSignerCert(ctx, header.X5U)
	if err != nil {
		return nil, 0, fmt.Errorf("list signer certificate: %w", err)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, 0, errors.New("list signer certificate is outside its validity period")
	}
	if !strings.Contains(strings.ToUpper(cert.Issuer.String()+cert.Subject.String()), "STI-PA") {
		return nil, 0, errors.New("list signer certificate does not name the STI-PA")
	}
	if t.ListPolicy.PinSPKI != "" {
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if base64.StdEncoding.EncodeToString(sum[:]) != strings.TrimSpace(t.ListPolicy.PinSPKI) {
			return nil, 0, errors.New("list signer certificate does not match FALCON_SHAKEN_PA_PIN")
		}
	}
	if t.ListPolicy.Roots != nil {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: t.ListPolicy.Roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return nil, 0, fmt.Errorf("list signer certificate does not chain to the STI-PA root: %w", err)
		}
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, 0, errors.New("list signer key is not ECDSA")
	}
	sig, err := b64(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, 0, errors.New("caList signature is not a 64 byte ES256 signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, 0, errors.New("caList signature does not verify")
	}
	if body.Exp > 0 && now.Unix() > body.Exp {
		return nil, 0, fmt.Errorf("caList expired at %s", time.Unix(body.Exp, 0).UTC().Format(time.RFC3339))
	}
	if lastSeq > 0 && body.Sequence > 0 && body.Sequence < lastSeq {
		return nil, 0, fmt.Errorf("%w (%d < %d)", errListRollback, body.Sequence, lastSeq)
	}
	return payload, body.Sequence, nil
}

func sameOrigin(x5u, listURL string) error {
	xu, err := url.Parse(x5u)
	if err != nil || xu.Scheme != "https" || xu.Host == "" {
		return errors.New("caList x5u must be an https URL")
	}
	lu, err := url.Parse(listURL)
	if err != nil || lu.Host == "" {
		return errors.New("list URL has no host")
	}
	if !strings.EqualFold(xu.Hostname(), lu.Hostname()) {
		return fmt.Errorf("caList x5u host %q differs from list host %q", xu.Hostname(), lu.Hostname())
	}
	return nil
}

// listSignerCert fetches and caches the certificate named by the list.
func (t *TrustStore) listSignerCert(ctx context.Context, x5u string) (*x509.Certificate, error) {
	t.signer.mu.Lock()
	defer t.signer.mu.Unlock()
	if t.signer.cert != nil && t.signer.url == x5u && time.Since(t.signer.at) < 24*time.Hour {
		return t.signer.cert, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, x5u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := t.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	certs := ParseCertificates(raw)
	if len(certs) == 0 {
		return nil, errors.New("no certificate at x5u")
	}
	t.signer.cert, t.signer.url, t.signer.at = certs[0], x5u, time.Now()
	return certs[0], nil
}

// parseSignedList is ParseCAList for a URL fetch: the JWS is verified.
func (t *TrustStore) parseSignedList(ctx context.Context, raw []byte, listURL string, lastSeq int64) ([]*x509.Certificate, int64, error) {
	text := strings.TrimSpace(string(raw))
	var envelope struct {
		CAList string `json:"caList"`
	}
	jws := ""
	if strings.HasPrefix(text, "{") && json.Unmarshal(raw, &envelope) == nil && envelope.CAList != "" {
		jws = envelope.CAList
	} else if strings.Count(text, ".") == 2 && !strings.Contains(text, "-----BEGIN") {
		jws = text
	}
	if jws == "" {
		// Plain PEM or an unsigned envelope: nothing to verify.
		if t.ListPolicy.Verify && t.CAURL != "" {
			return nil, 0, errors.New("CA list from URL is not signed; set FALCON_SHAKEN_VERIFY_LIST=false only in a lab")
		}
		return ParseCAList(raw)
	}
	payload, seq, err := t.verifySignedList(ctx, jws, listURL, lastSeq)
	if err != nil {
		return nil, 0, err
	}
	var body struct {
		TrustList []string `json:"trustList"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, 0, err
	}
	certs := certsFromPEMs(body.TrustList)
	if len(certs) == 0 {
		return nil, 0, errors.New("caList carries no certificates")
	}
	return certs, seq, nil
}
