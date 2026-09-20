package shaken

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Default STI-PA endpoints. The CA list is public JSON that carries a JWS
// whose payload holds the trusted root PEMs. The CRL is a PEM X.509 CRL.
const (
	DefaultCAListURL = "https://authenticate-api.iconectiv.com/api/v1/ca-list"
	DefaultCRLURL    = "https://authenticate-api.iconectiv.com/download/v1/crl"
)

// TrustStore holds the STI-CA roots and the STI-PA CRL, refreshed on timers.
type TrustStore struct {
	CAURL      string
	CAFile     string
	CRLURL     string
	CARefresh  time.Duration
	CRLRefresh time.Duration
	HTTP       *http.Client
	// ListPolicy governs the signed CA list check. Verify defaults to on.
	ListPolicy ListPolicy

	signer    listSigner
	mu        sync.RWMutex
	roots     *x509.CertPool
	rootCount int
	sequence  int64
	revoked   map[string]struct{}
	caAt      time.Time
	crlAt     time.Time
	caErr     string
	crlErr    string
}

// NewTrustStore returns a store with the given sources. Empty URL and file
// means no roots, and every chain check reports as unchecked.
func NewTrustStore(caURL, caFile, crlURL string) *TrustStore {
	return &TrustStore{
		CAURL:      strings.TrimSpace(caURL),
		CAFile:     strings.TrimSpace(caFile),
		CRLURL:     strings.TrimSpace(crlURL),
		CARefresh:  6 * time.Hour,
		CRLRefresh: time.Hour,
		HTTP:       &http.Client{Timeout: 30 * time.Second},
		ListPolicy: ListPolicy{Verify: true},
		revoked:    map[string]struct{}{},
	}
}

// Enabled reports whether any root source is configured.
func (t *TrustStore) Enabled() bool {
	return t != nil && (t.CAURL != "" || t.CAFile != "")
}

// HasRoots reports whether at least one root is loaded.
func (t *TrustStore) HasRoots() bool {
	if t == nil {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.rootCount > 0
}

// Status is what the dashboard shows.
type Status struct {
	Configured bool      `json:"configured"`
	Roots      int       `json:"roots"`
	Sequence   int64     `json:"sequence"`
	RootsAt    time.Time `json:"roots_loaded_at"`
	RootsError string    `json:"roots_error,omitempty"`
	Revoked    int       `json:"revoked"`
	CRLAt      time.Time `json:"crl_loaded_at"`
	CRLError   string    `json:"crl_error,omitempty"`
	CAURL      string    `json:"ca_url,omitempty"`
	CRLURL     string    `json:"crl_url,omitempty"`
}

// Status reports load state.
func (t *TrustStore) Status() Status {
	if t == nil {
		return Status{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return Status{
		Configured: t.Enabled(),
		Roots:      t.rootCount,
		Sequence:   t.sequence,
		RootsAt:    t.caAt,
		RootsError: t.caErr,
		Revoked:    len(t.revoked),
		CRLAt:      t.crlAt,
		CRLError:   t.crlErr,
		CAURL:      t.CAURL,
		CRLURL:     t.CRLURL,
	}
}

// Run loads once, then refreshes until ctx ends.
func (t *TrustStore) Run(ctx context.Context) {
	if !t.Enabled() {
		return
	}
	t.LoadRoots(ctx)
	t.LoadCRL(ctx)
	ca := time.NewTicker(t.CARefresh)
	crl := time.NewTicker(t.CRLRefresh)
	defer ca.Stop()
	defer crl.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ca.C:
			t.LoadRoots(ctx)
		case <-crl.C:
			t.LoadCRL(ctx)
		}
	}
}

// LoadRoots reads the CA list from the URL and the file. A failed source
// keeps the previous roots and records the error.
func (t *TrustStore) LoadRoots(ctx context.Context) {
	pool := x509.NewCertPool()
	count := 0
	var seq int64
	var errs []string
	if t.CAURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.CAURL, nil)
		if err == nil {
			resp, derr := t.HTTP.Do(req)
			if derr != nil {
				err = derr
			} else {
				func() {
					defer resp.Body.Close()
					if resp.StatusCode >= 300 {
						err = fmt.Errorf("%s", resp.Status)
						return
					}
					raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
					if rerr != nil {
						err = rerr
						return
					}
					t.mu.RLock()
					lastSeq := t.sequence
					t.mu.RUnlock()
					certs, s, perr := t.parseSignedList(ctx, raw, t.CAURL, lastSeq)
					if perr != nil {
						err = perr
						return
					}
					seq = s
					for _, c := range certs {
						pool.AddCert(c)
						count++
					}
				}()
			}
		}
		if err != nil {
			errs = append(errs, "url: "+err.Error())
		}
	}
	if t.CAFile != "" {
		raw, err := os.ReadFile(t.CAFile)
		if err != nil {
			errs = append(errs, "file: "+err.Error())
		} else {
			for _, c := range ParseCertificates(raw) {
				pool.AddCert(c)
				count++
			}
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if count == 0 {
		// Keep the last good list. A failed refresh must not empty the
		// trust store and turn every signer untrusted.
		t.caErr = strings.Join(errs, "; ")
		if t.caErr == "" {
			t.caErr = "no certificates found"
		}
		log.Printf("falcon shaken: roots: %s (keeping %d roots from sequence %d)", t.caErr, t.rootCount, t.sequence)
		return
	}
	t.roots, t.rootCount, t.sequence = pool, count, seq
	t.caAt = time.Now().UTC()
	t.caErr = strings.Join(errs, "; ")
	log.Printf("falcon shaken: loaded %d STI-CA roots (sequence %d)", count, seq)
}

// LoadCRL reads the STI-PA CRL and indexes revoked serials.
func (t *TrustStore) LoadCRL(ctx context.Context) {
	if t.CRLURL == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.CRLURL, nil)
	if err != nil {
		t.setCRLErr(err.Error())
		return
	}
	resp, err := t.HTTP.Do(req)
	if err != nil {
		t.setCRLErr(err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.setCRLErr(resp.Status)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		t.setCRLErr(err.Error())
		return
	}
	revoked, err := ParseCRL(raw)
	if err != nil {
		t.setCRLErr(err.Error())
		return
	}
	t.mu.Lock()
	t.revoked = revoked
	t.crlAt = time.Now().UTC()
	t.crlErr = ""
	t.mu.Unlock()
	log.Printf("falcon shaken: loaded CRL with %d revoked serials", len(revoked))
}

func (t *TrustStore) setCRLErr(msg string) {
	t.mu.Lock()
	t.crlErr = msg
	t.mu.Unlock()
	log.Printf("falcon shaken: crl: %s", msg)
}

// VerifyChain checks that the leaf chains to a trusted root. Intermediates
// come from the fetched chain. Key usage is not constrained because SHAKEN
// certificates carry no TLS purpose.
func (t *TrustStore) VerifyChain(chain []*x509.Certificate, now time.Time) error {
	t.mu.RLock()
	roots := t.roots
	t.mu.RUnlock()
	if roots == nil {
		return errors.New("no roots")
	}
	leaf := chain[0]
	// TNAuthList is not a critical extension Go knows. Some CAs mark it
	// critical anyway. It is read separately, so drop it from the check.
	var keep []asn1.ObjectIdentifier
	for _, oid := range leaf.UnhandledCriticalExtensions {
		if !oid.Equal(oidTNAuthList) {
			keep = append(keep, oid)
		}
	}
	leaf.UnhandledCriticalExtensions = keep
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// IsRevoked reports whether the leaf serial is on the CRL.
func (t *TrustStore) IsRevoked(leaf *x509.Certificate) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.revoked[leaf.SerialNumber.Text(16)]
	return ok
}

// ParseCAList accepts the STI-PA JSON envelope with a caList JWS, a bare
// JSON object with trustList, a JWS on its own, or a PEM bundle. It returns
// the certificates and the list sequence when present.
func ParseCAList(raw []byte) ([]*x509.Certificate, int64, error) {
	text := strings.TrimSpace(string(raw))
	var envelope struct {
		CAList    string   `json:"caList"`
		TrustList []string `json:"trustList"`
		Sequence  int64    `json:"sequence"`
	}
	if strings.HasPrefix(text, "{") && json.Unmarshal(raw, &envelope) == nil {
		if envelope.CAList != "" {
			return certsFromJWS(envelope.CAList)
		}
		if len(envelope.TrustList) > 0 {
			return certsFromPEMs(envelope.TrustList), envelope.Sequence, nil
		}
	}
	if strings.Count(text, ".") == 2 && !strings.Contains(text, "-----BEGIN") {
		return certsFromJWS(text)
	}
	certs := ParseCertificates(raw)
	if len(certs) == 0 {
		return nil, 0, errors.New("no certificates found in CA list")
	}
	return certs, 0, nil
}

func certsFromJWS(jws string) ([]*x509.Certificate, int64, error) {
	parts := strings.Split(strings.TrimSpace(jws), ".")
	if len(parts) != 3 {
		return nil, 0, errors.New("caList is not a JWS")
	}
	payload, err := b64(parts[1])
	if err != nil {
		return nil, 0, err
	}
	var body struct {
		Sequence  int64    `json:"sequence"`
		TrustList []string `json:"trustList"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, 0, err
	}
	certs := certsFromPEMs(body.TrustList)
	if len(certs) == 0 {
		return nil, 0, errors.New("caList carries no certificates")
	}
	return certs, body.Sequence, nil
}

func certsFromPEMs(pems []string) []*x509.Certificate {
	var out []*x509.Certificate
	for _, p := range pems {
		out = append(out, ParseCertificates([]byte(p))...)
	}
	return out
}

// ParseCRL reads a PEM or DER X.509 CRL and returns revoked serials in hex.
func ParseCRL(raw []byte) (map[string]struct{}, error) {
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		der = block.Bytes
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(crl.RevokedCertificateEntries))
	for _, e := range crl.RevokedCertificateEntries {
		out[e.SerialNumber.Text(16)] = struct{}{}
	}
	return out, nil
}
