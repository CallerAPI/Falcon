// Package shaken verifies STIR/SHAKEN Identity headers.
//
// A PASSporT is a JWS signed with ES256. The header names the certificate URL
// (x5u). Verification fetches that certificate, checks the signature, checks
// the chain against the STI-PA list of trusted CAs, checks the STI-PA CRL,
// checks freshness and the orig/dest claims, and reads the signer's Service
// Provider Code from the TNAuthList extension. The SPC is the signer's
// identity: the provider that attested the call.
//
// The switch never waits on a cold cache. A certificate fetch that misses
// the per-call budget returns No-TN-Validation and warms the cache in the
// background for the next call.
package shaken

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/callerapi/falcon/internal/safehttp"
)

// Verstat values follow ATIS-1000074 and the verstat parameter carriers add
// to P-Asserted-Identity.
const (
	VerstatPassed = "TN-Validation-Passed"
	VerstatFailed = "TN-Validation-Failed"
	VerstatNone   = "No-TN-Validation"
)

var oidTNAuthList = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 26}

// Signer is the certificate identity behind a PASSporT.
type Signer struct {
	SPC       string    `json:"spc,omitempty"`
	CN        string    `json:"cn,omitempty"`
	Org       string    `json:"org,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	Serial    string    `json:"serial,omitempty"`
	NotBefore time.Time `json:"not_before,omitempty"`
	NotAfter  time.Time `json:"not_after,omitempty"`
	X5UHost   string    `json:"x5u_host,omitempty"`
}

// Result is one verification.
type Result struct {
	Present   bool     `json:"present"`
	ParsedJWT bool     `json:"parsed_jwt"`
	Alg       string   `json:"alg,omitempty"`
	PPT       string   `json:"ppt,omitempty"`
	X5U       string   `json:"x5u,omitempty"`
	Attest    string   `json:"attest,omitempty"`
	OrigTN    string   `json:"orig_tn,omitempty"`
	OrigID    string   `json:"origid,omitempty"`
	DestTN    []string `json:"dest_tn,omitempty"`
	IAT       int64    `json:"iat,omitempty"`
	Verstat   string   `json:"verstat"`
	Signature bool     `json:"signature_ok"`
	Chain     bool     `json:"chain_trusted"`
	CertValid bool     `json:"cert_valid"`
	Revoked   bool     `json:"revoked"`
	Fresh     bool     `json:"fresh"`
	OrigMatch bool     `json:"orig_matches_from"`
	DestMatch bool     `json:"dest_matches_to"`
	Pending   bool     `json:"pending"`
	Cached    bool     `json:"cached"`
	Signer    Signer   `json:"signer"`
	Errors    []string `json:"errors,omitempty"`
	Latency   int64    `json:"latency_ms"`
}

// Options tune the verifier.
type Options struct {
	// Budget is how long one screen waits for a cold certificate fetch.
	Budget time.Duration
	// FetchTimeout bounds the background fetch itself.
	FetchTimeout time.Duration
	// CertTTL is how long a fetched chain is trusted from cache.
	CertTTL time.Duration
	// NegativeTTL is how long a failed fetch is remembered.
	NegativeTTL time.Duration
	// MaxAge is the accepted distance between iat and now.
	MaxAge time.Duration
	// AllowHTTP is lab mode: plain http x5u and private destinations are
	// accepted. Never in production. The x5u comes from a stranger.
	AllowHTTP bool
	// MaxCerts bounds the cache.
	MaxCerts int
	// MaxInflight bounds concurrent certificate fetches.
	MaxInflight int
	// MaxFetchPerSecond bounds new fetches per second across all x5u.
	MaxFetchPerSecond int
	// MaxChain bounds certificates accepted from one x5u.
	MaxChain int
}

// DefaultOptions are the shipped values.
func DefaultOptions() Options {
	return Options{
		Budget:            400 * time.Millisecond,
		FetchTimeout:      4 * time.Second,
		CertTTL:           time.Hour,
		NegativeTTL:       2 * time.Minute,
		MaxAge:            60 * time.Second,
		MaxCerts:          5000,
		MaxInflight:       32,
		MaxFetchPerSecond: 50,
		MaxChain:          8,
	}
}

type cached struct {
	chain   []*x509.Certificate
	err     error
	expires time.Time
}

// Verifier verifies PASSporTs against a trust store.
type Verifier struct {
	Trust  *TrustStore
	HTTP   *http.Client
	Policy safehttp.Policy
	Opts   Options
	Now    func() time.Time

	mu       sync.Mutex
	certs    map[string]*cached
	inflight map[string]chan struct{}
	// Outbound fetch limiter: a semaphore for concurrency and a one second
	// token bucket for rate. Both protect the signers' certificate servers
	// and the operator's egress from a flood of unique x5u values.
	sem        chan struct{}
	bucketAt   time.Time
	bucketLeft int
}

// New returns a verifier with the given trust store.
func New(trust *TrustStore, opts Options) *Verifier {
	def := DefaultOptions()
	if opts.Budget <= 0 {
		opts.Budget = def.Budget
	}
	if opts.FetchTimeout <= 0 {
		opts.FetchTimeout = def.FetchTimeout
	}
	if opts.CertTTL <= 0 {
		opts.CertTTL = def.CertTTL
	}
	if opts.NegativeTTL <= 0 {
		opts.NegativeTTL = def.NegativeTTL
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = def.MaxAge
	}
	if opts.MaxCerts <= 0 {
		opts.MaxCerts = def.MaxCerts
	}
	if opts.MaxInflight <= 0 {
		opts.MaxInflight = def.MaxInflight
	}
	if opts.MaxFetchPerSecond <= 0 {
		opts.MaxFetchPerSecond = def.MaxFetchPerSecond
	}
	if opts.MaxChain <= 0 {
		opts.MaxChain = def.MaxChain
	}
	policy := safehttp.DefaultPolicy()
	policy.Timeout = opts.FetchTimeout
	policy.AllowHTTP = opts.AllowHTTP
	policy.AllowPrivate = opts.AllowHTTP
	return &Verifier{
		Trust:    trust,
		HTTP:     policy.Client(),
		Policy:   policy,
		Opts:     opts,
		Now:      time.Now,
		certs:    map[string]*cached{},
		inflight: map[string]chan struct{}{},
		sem:      make(chan struct{}, opts.MaxInflight),
	}
}

// Verify checks one Identity header value. fromTN and toTN are the E.164
// numbers the SIP message carries; empty means do not compare.
func (v *Verifier) Verify(ctx context.Context, identity, fromTN, toTN string) Result {
	start := v.Now()
	r := Result{Verstat: VerstatNone}
	defer func() { r.Latency = v.Now().Sub(start).Milliseconds() }()

	identity = strings.TrimSpace(identity)
	if identity == "" {
		return r
	}
	r.Present = true

	jwt, params := splitIdentity(identity)
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		r.Errors = append(r.Errors, "identity is not a three part JWS")
		return r
	}
	hdrRaw, err := b64(parts[0])
	if err != nil {
		r.Errors = append(r.Errors, "header is not base64url")
		return r
	}
	var hdr struct {
		Alg string `json:"alg"`
		PPT string `json:"ppt"`
		Typ string `json:"typ"`
		X5U string `json:"x5u"`
	}
	if json.Unmarshal(hdrRaw, &hdr) != nil {
		r.Errors = append(r.Errors, "header is not JSON")
		return r
	}
	payloadRaw, err := b64(parts[1])
	if err != nil {
		r.Errors = append(r.Errors, "payload is not base64url")
		return r
	}
	var body struct {
		Attest string `json:"attest"`
		OrigID string `json:"origid"`
		IAT    int64  `json:"iat"`
		Orig   struct {
			TN string `json:"tn"`
		} `json:"orig"`
		Dest struct {
			TN []string `json:"tn"`
		} `json:"dest"`
	}
	if json.Unmarshal(payloadRaw, &body) != nil {
		r.Errors = append(r.Errors, "payload is not JSON")
		return r
	}
	r.ParsedJWT = true
	r.Alg, r.PPT = hdr.Alg, firstNonEmpty(hdr.PPT, params["ppt"])
	r.X5U = firstNonEmpty(hdr.X5U, strings.Trim(params["info"], "<>"))
	r.Attest = strings.ToUpper(strings.TrimSpace(body.Attest))
	r.OrigTN = digits(body.Orig.TN)
	r.OrigID = body.OrigID
	r.IAT = body.IAT
	for _, tn := range body.Dest.TN {
		r.DestTN = append(r.DestTN, digits(tn))
	}
	if u, err := url.Parse(r.X5U); err == nil {
		r.Signer.X5UHost = u.Host
	}

	now := v.Now()
	if r.IAT > 0 {
		d := now.Unix() - r.IAT
		if d < 0 {
			d = -d
		}
		r.Fresh = time.Duration(d)*time.Second <= v.Opts.MaxAge
	}
	if fromTN != "" && r.OrigTN != "" {
		r.OrigMatch = digits(fromTN) == r.OrigTN
	}
	if toTN != "" && len(r.DestTN) > 0 {
		want := digits(toTN)
		for _, d := range r.DestTN {
			if d == want {
				r.DestMatch = true
			}
		}
	}

	// Anything below here can fail the call. Everything above only
	// describes it.
	r.Verstat = VerstatFailed
	if !strings.EqualFold(hdr.Alg, "ES256") {
		r.Errors = append(r.Errors, "alg is "+hdr.Alg+", ES256 required")
		return r
	}
	if r.X5U == "" {
		r.Errors = append(r.Errors, "no x5u certificate URL")
		return r
	}
	if _, err := v.Policy.ValidateURL(r.X5U); err != nil {
		r.Errors = append(r.Errors, "x5u rejected: "+err.Error())
		return r
	}

	chain, cachedHit, pending, ferr := v.chain(ctx, r.X5U)
	r.Cached = cachedHit
	if pending {
		r.Pending = true
		r.Verstat = VerstatNone
		r.Errors = append(r.Errors, "certificate fetch exceeded the per-call budget; warming cache")
		return r
	}
	if ferr != nil {
		r.Verstat = VerstatNone
		r.Errors = append(r.Errors, "certificate fetch: "+ferr.Error())
		return r
	}
	leaf := chain[0]
	r.Signer.CN = leaf.Subject.CommonName
	if len(leaf.Subject.Organization) > 0 {
		r.Signer.Org = leaf.Subject.Organization[0]
	}
	r.Signer.Issuer = leaf.Issuer.CommonName
	r.Signer.Serial = leaf.SerialNumber.Text(16)
	r.Signer.NotBefore, r.Signer.NotAfter = leaf.NotBefore, leaf.NotAfter
	r.Signer.SPC = spcFromCert(leaf)

	sig, err := b64(parts[2])
	if err != nil {
		r.Errors = append(r.Errors, "signature is not base64url")
		return r
	}
	r.Signature = verifyES256(leaf, []byte(parts[0]+"."+parts[1]), sig)
	if !r.Signature {
		r.Errors = append(r.Errors, "signature does not verify with the x5u certificate")
	}
	r.CertValid = !now.Before(leaf.NotBefore) && !now.After(leaf.NotAfter)
	if !r.CertValid {
		r.Errors = append(r.Errors, "certificate is outside its validity period")
	}
	if v.Trust != nil && v.Trust.HasRoots() {
		if err := v.Trust.VerifyChain(chain, now); err != nil {
			r.Errors = append(r.Errors, "chain: "+err.Error())
		} else {
			r.Chain = true
		}
		if v.Trust.IsRevoked(leaf) {
			r.Revoked = true
			r.Errors = append(r.Errors, "certificate serial is on the STI-PA CRL")
		}
	} else {
		r.Errors = append(r.Errors, "no trusted STI-CA roots loaded; chain not checked")
	}
	if r.IAT > 0 && !r.Fresh {
		r.Errors = append(r.Errors, fmt.Sprintf("iat is %ds from now", now.Unix()-r.IAT))
	}
	if fromTN != "" && r.OrigTN != "" && !r.OrigMatch {
		r.Errors = append(r.Errors, "orig tn does not match the calling number")
	}

	if r.Signature && r.CertValid && r.Chain && !r.Revoked && (r.IAT == 0 || r.Fresh) && (fromTN == "" || r.OrigTN == "" || r.OrigMatch) {
		r.Verstat = VerstatPassed
	}
	return r
}

// CachedChainPEM returns the cached chain for an x5u as PEM, or nil when
// the cache has no fresh entry. Used by the traceback pack.
func (v *Verifier) CachedChainPEM(x5u string) []byte {
	if v == nil || x5u == "" {
		return nil
	}
	v.mu.Lock()
	c, ok := v.certs[x5u]
	v.mu.Unlock()
	if !ok || c == nil || len(c.chain) == 0 {
		return nil
	}
	var out []byte
	for _, cert := range c.chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return out
}

// chain returns the certificate chain for an x5u, from cache when fresh. On
// a miss it starts one fetch and waits up to the budget. When the budget
// passes first, pending is true and the fetch continues in the background.
func (v *Verifier) chain(ctx context.Context, x5u string) (chain []*x509.Certificate, hit, pending bool, err error) {
	now := v.Now()
	v.mu.Lock()
	if c, ok := v.certs[x5u]; ok && now.Before(c.expires) {
		v.mu.Unlock()
		return c.chain, true, false, c.err
	}
	done, running := v.inflight[x5u]
	if !running {
		done = make(chan struct{})
		v.inflight[x5u] = done
		go v.fetch(x5u, done)
	}
	v.mu.Unlock()

	budget := time.NewTimer(v.Opts.Budget)
	defer budget.Stop()
	select {
	case <-done:
	case <-budget.C:
		return nil, false, true, nil
	case <-ctx.Done():
		return nil, false, true, nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if c, ok := v.certs[x5u]; ok {
		return c.chain, false, false, c.err
	}
	return nil, false, false, errors.New("fetch produced no result")
}

// errThrottled marks a fetch that was refused by the limiter. It is cached
// for a short time so the next call for the same x5u tries again soon.
var errThrottled = errors.New("certificate fetch throttled")

func (v *Verifier) fetch(x5u string, done chan struct{}) {
	defer func() {
		v.mu.Lock()
		delete(v.inflight, x5u)
		v.mu.Unlock()
		close(done)
	}()
	var chain []*x509.Certificate
	err := errThrottled
	if v.takeToken() {
		select {
		case v.sem <- struct{}{}:
			ctx, cancel := context.WithTimeout(context.Background(), v.Opts.FetchTimeout)
			chain, err = v.download(ctx, x5u)
			cancel()
			<-v.sem
		default:
		}
	}
	now := v.Now()
	entry := &cached{chain: chain, err: err, expires: now.Add(v.Opts.CertTTL)}
	if err != nil {
		entry.expires = now.Add(v.Opts.NegativeTTL)
		if errors.Is(err, errThrottled) {
			entry.expires = now.Add(15 * time.Second)
		}
	}
	v.mu.Lock()
	if len(v.certs) >= v.Opts.MaxCerts {
		for k, c := range v.certs {
			if now.After(c.expires) {
				delete(v.certs, k)
			}
		}
		if len(v.certs) >= v.Opts.MaxCerts {
			v.certs = map[string]*cached{}
		}
	}
	v.certs[x5u] = entry
	v.mu.Unlock()
}

// takeToken spends one fetch from the per-second bucket.
func (v *Verifier) takeToken() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.Now()
	if now.Sub(v.bucketAt) >= time.Second {
		v.bucketAt = now
		v.bucketLeft = v.Opts.MaxFetchPerSecond
	}
	if v.bucketLeft <= 0 {
		return false
	}
	v.bucketLeft--
	return true
}

func (v *Verifier) download(ctx context.Context, x5u string) ([]*x509.Certificate, error) {
	raw, status, err := v.Policy.Get(ctx, v.HTTP, x5u, "application/pem-certificate-chain, application/pkix-cert, */*")
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, fmt.Errorf("http %d", status)
	}
	chain := ParseCertificates(raw)
	if len(chain) == 0 {
		return nil, errors.New("no certificate in response")
	}
	if len(chain) > v.Opts.MaxChain {
		chain = chain[:v.Opts.MaxChain]
	}
	return chain, nil
}

// ParseCertificates reads every PEM CERTIFICATE block, or one DER
// certificate when there is no PEM.
func ParseCertificates(raw []byte) []*x509.Certificate {
	var out []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		if c, err := x509.ParseCertificate(raw); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// CacheStats reports cache size for the status endpoint.
func (v *Verifier) CacheStats() (certs, inflight int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.certs), len(v.inflight)
}

func verifyES256(cert *x509.Certificate, signingInput, sig []byte) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	sum := sha256.Sum256(signingInput)
	if len(sig) == 64 {
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(pub, sum[:], r, s)
	}
	// Some signers emit a DER sequence instead of the JWS r||s form.
	return ecdsa.VerifyASN1(pub, sum[:], sig)
}

// spcFromCert reads the first SPC in the TNAuthList extension. RFC 8226
// uses explicit tags, so the [0] wraps an IA5String. Implicit encodings are
// accepted as well.
func spcFromCert(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidTNAuthList) {
			continue
		}
		var entries []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &entries); err != nil {
			return ""
		}
		for _, e := range entries {
			if e.Class != asn1.ClassContextSpecific || e.Tag != 0 {
				continue
			}
			if e.IsCompound {
				var s string
				if _, err := asn1.UnmarshalWithParams(e.Bytes, &s, "ia5"); err == nil {
					return strings.TrimSpace(s)
				}
				var raw asn1.RawValue
				if _, err := asn1.Unmarshal(e.Bytes, &raw); err == nil {
					return strings.TrimSpace(string(raw.Bytes))
				}
				continue
			}
			return strings.TrimSpace(string(e.Bytes))
		}
	}
	return ""
}

func splitIdentity(raw string) (jwt string, params map[string]string) {
	params = map[string]string{}
	fields := strings.Split(raw, ";")
	jwt = strings.TrimSpace(fields[0])
	for _, f := range fields[1:] {
		k, val, ok := strings.Cut(strings.TrimSpace(f), "=")
		if !ok {
			continue
		}
		params[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(val)
	}
	return jwt, params
}

func b64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
