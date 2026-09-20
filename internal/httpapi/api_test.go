package httpapi

import (
	"bufio"
	"bytes"
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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/shaken"
	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/voice"
)

func newTestServer(t *testing.T) (*Server, *store.SQLite) {
	t.Helper()
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := &Server{
		Cfg:       config.Config{FailOpen: true, Token: "secret", RetentionDays: 30, StoreRawSIP: true},
		Engine:    score.NewEngine(score.Thresholds{Flag: 40, Challenge: 60, Reject: 80}, score.Limits{Window: time.Minute, IP: 30, From: 20, Scan: 15}),
		Store:     db,
		InstallID: "test",
	}
	srv.Sampler = &voice.Sampler{Store: db, Budget: voice.DefaultBudget(), Enabled: true}
	if err := srv.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return srv, db
}

func do(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body == nil {
		rd = bytes.NewReader(nil)
	} else if s, ok := body.(string); ok {
		rd = bytes.NewReader([]byte(s))
	} else {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Falcon-Token", "secret")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func cleanInvite(from, ua string) string {
	return "INVITE sip:+15551212@ex SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 198.51.100.20;branch=z9hG4bK1\r\n" +
		"From: <sip:" + from + "@ex>;tag=1\r\n" +
		"To: <sip:+15551212@ex>\r\n" +
		"Call-ID: demo-" + from + "\r\n" +
		"User-Agent: " + ua + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 0\r\n\r\n" +
		"v=0\r\no=- 1 1 IN IP4 198.51.100.20\r\nc=IN IP4 198.51.100.20\r\nm=audio 4000 RTP/AVP 0\r\n"
}

func screen(t *testing.T, srv *Server, ip, raw string) score.Result {
	t.Helper()
	w := do(t, srv, http.MethodPost, "/v1/screen", map[string]string{"switch": "test", "source_ip": ip, "raw_sip": raw})
	if w.Code != 200 {
		t.Fatalf("screen status %d body %s", w.Code, w.Body.String())
	}
	var res score.Result
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func waitEvents(t *testing.T, db *store.SQLite, n int) []store.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		events, err := db.Recent(context.Background(), 50)
		if err == nil && len(events) >= n {
			return events
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("only saw fewer than %d events", n)
	return nil
}

func TestRulesDenyAndAllow(t *testing.T) {
	srv, db := newTestServer(t)

	w := do(t, srv, http.MethodPost, "/v1/rules", map[string]string{"kind": "deny", "subject": "number", "value": "+1 (415) 555-0100", "note": "known fraud desk"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create deny: %d %s", w.Code, w.Body.String())
	}
	w = do(t, srv, http.MethodPost, "/v1/rules", map[string]string{"kind": "allow", "subject": "ip", "value": "203.0.113.0/24", "note": "our own SBCs", "ttl": "1h"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create allow: %d %s", w.Code, w.Body.String())
	}
	w = do(t, srv, http.MethodPost, "/v1/rules", map[string]string{"kind": "allow", "subject": "ip", "value": "garbage"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad rule accepted: %d", w.Code)
	}

	denied := screen(t, srv, "198.51.100.20", cleanInvite("+14155550100", "Acme-SBC/1.0"))
	if denied.Action != score.ActionReject || denied.Headers["X-Falcon-Block"] != "denylist" || denied.Signals.ListKind != "deny" {
		t.Fatalf("deny rule did not reject: %+v", denied)
	}

	// A scanner from an allowed range still passes. Allow ends scoring.
	allowed := screen(t, srv, "203.0.113.9", cleanInvite("+19995550100", "friendly-scanner"))
	if allowed.Action != score.ActionAllow || allowed.RiskScore != 0 || allowed.Signals.ListKind != "allow" {
		t.Fatalf("allow rule did not bypass: %+v", allowed)
	}
	if len(allowed.Reasons) != 1 || allowed.Reasons[0].Code != "allowlist_ip" {
		t.Fatalf("allow reasons: %+v", allowed.Reasons)
	}

	w = do(t, srv, http.MethodGet, "/v1/rules", nil)
	var list struct {
		Data []struct {
			ID    int64  `json:"id"`
			Value string `json:"value"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Data) != 2 || list.Data[1].Value != "+14155550100" {
		t.Fatalf("rules list: %+v", list.Data)
	}
	w = do(t, srv, http.MethodDelete, "/v1/rules/"+itoa(list.Data[1].ID), nil)
	if w.Code != 200 {
		t.Fatalf("delete: %d", w.Code)
	}
	after := screen(t, srv, "198.51.100.20", cleanInvite("+14155550100", "Acme-SBC/1.0"))
	if after.Action == score.ActionReject {
		t.Fatalf("deleted deny still rejects: %+v", after)
	}
	waitEvents(t, db, 3)
}

func TestEventsFilterCursorPartiesHistogramCSVMetrics(t *testing.T) {
	srv, db := newTestServer(t)
	for i := 0; i < 6; i++ {
		screen(t, srv, "198.51.100.20", cleanInvite("+1415555010"+itoa(int64(i)), "Acme-SBC/1.0"))
	}
	screen(t, srv, "192.0.2.7", cleanInvite("+19995550100", "friendly-scanner"))
	waitEvents(t, db, 7)

	w := do(t, srv, http.MethodGet, "/v1/events?action=reject&range=1h", nil)
	var page struct {
		Data       []store.Event `json:"data"`
		NextBefore int64         `json:"next_before"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Data) != 1 || page.Data[0].SourceIP != "192.0.2.7" {
		t.Fatalf("action filter: %+v", page.Data)
	}

	w = do(t, srv, http.MethodGet, "/v1/events?limit=4", nil)
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Data) != 4 || page.NextBefore == 0 {
		t.Fatalf("first page: %d next=%d", len(page.Data), page.NextBefore)
	}
	w = do(t, srv, http.MethodGet, "/v1/events?limit=4&before="+itoa(page.NextBefore), nil)
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Data) != 3 {
		t.Fatalf("second page: %d", len(page.Data))
	}

	w = do(t, srv, http.MethodGet, "/v1/events?q=5550103", nil)
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Data) != 1 || page.Data[0].From != "+14155550103" {
		t.Fatalf("q filter: %+v", page.Data)
	}

	w = do(t, srv, http.MethodGet, "/v1/parties?by=ip&range=1h", nil)
	var parties struct {
		Data []store.Party `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &parties)
	if len(parties.Data) != 2 || parties.Data[0].Name != "198.51.100.20" || parties.Data[0].Total != 6 || parties.Data[0].Distinct != 6 {
		t.Fatalf("parties: %+v", parties.Data)
	}
	if do(t, srv, http.MethodGet, "/v1/parties?by=nonsense", nil).Code != http.StatusBadRequest {
		t.Fatal("bad grouping accepted")
	}

	w = do(t, srv, http.MethodGet, "/v1/histogram?range=1h", nil)
	var hist struct {
		Buckets    []int          `json:"buckets"`
		Thresholds map[string]int `json:"thresholds"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &hist)
	if len(hist.Buckets) != 10 || hist.Buckets[9] != 1 || hist.Thresholds["reject"] != 80 {
		t.Fatalf("histogram: %+v", hist)
	}
	sum := 0
	for _, n := range hist.Buckets {
		sum += n
	}
	if sum != 7 {
		t.Fatalf("histogram sums to %d", sum)
	}

	w = do(t, srv, http.MethodGet, "/v1/stats?range=1h", nil)
	var st store.Stats
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if st.Total != 7 || st.ByAction["reject"] != 1 || st.StepSeconds != 60 || len(st.Timeseries) < 55 {
		t.Fatalf("stats: total=%d reject=%d step=%d points=%d", st.Total, st.ByAction["reject"], st.StepSeconds, len(st.Timeseries))
	}
	if len(st.TopReasons) == 0 || st.TopReasons[0].Name != "scanner_user_agent" {
		t.Fatalf("top reasons: %+v", st.TopReasons)
	}

	w = do(t, srv, http.MethodGet, "/v1/events.csv?range=1h", nil)
	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	if len(lines) != 8 || !strings.HasPrefix(lines[0], "received_at,action,risk_score") {
		t.Fatalf("csv: %d lines, header %q", len(lines), lines[0])
	}

	w = do(t, srv, http.MethodGet, "/metrics", nil)
	body := w.Body.String()
	for _, want := range []string{"falcon_screens_total 7", `falcon_screens_by_action_total{action="reject"} 1`, "falcon_rules 0", "falcon_build_info"} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q in:\n%s", want, body)
		}
	}

	w = do(t, srv, http.MethodGet, "/v1/config", nil)
	if !strings.Contains(w.Body.String(), `"token":"set"`) || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("config leaks or lacks redaction: %s", w.Body.String())
	}
}

func TestStreamDeliversScreenedEvents(t *testing.T) {
	srv, _ := newTestServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/stream", nil)
	req.Header.Set("X-Falcon-Token", "secret")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	reader := bufio.NewReader(resp.Body)
	// First frame is the retry hint. Read past it.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	// Give the subscription a moment to register before publishing.
	time.Sleep(50 * time.Millisecond)
	screen(t, srv, "192.0.2.7", cleanInvite("+19995550100", "friendly-scanner"))

	var event, data string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "event: ") {
			event = strings.TrimPrefix(line, "event: ")
		}
		if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if event != "screen" {
		t.Fatalf("event name %q", event)
	}
	var ev store.Event
	if err := json.Unmarshal([]byte(data), &ev); err != nil || ev.Action != score.ActionReject || ev.RawSIP != "" {
		t.Fatalf("stream payload: %v %+v", err, ev)
	}
}

// A signed INVITE flows through verification into storage, signer stats,
// and headers, and a deny rule on the signer SPC rejects the next call.
func TestScreenVerifiesPassportAndDeniesBySigner(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)
	inner, _ := asn1.MarshalWithParams("8181", "ia5")
	entryDER, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner})
	tnAuth, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: entryDER})
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "SHAKEN 8181", Organization: []string{"Gateway Eight LLC"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 26}, Value: tnAuth}}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, rootCert, &leafKey.PublicKey, rootKey)
	chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	certSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(chainPEM) }))
	defer certSrv.Close()

	trust := shaken.NewTrustStore("", filepath.Join(t.TempDir(), "roots.pem"), "")
	if err := writeFile(trust.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})); err != nil {
		t.Fatal(err)
	}
	trust.LoadRoots(context.Background())
	opts := shaken.DefaultOptions()
	opts.AllowHTTP = true
	opts.Budget = 2 * time.Second

	srv, db := newTestServer(t)
	srv.Trust = trust
	srv.Verifier = shaken.New(trust, opts)

	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "ppt": "shaken", "typ": "passport", "x5u": certSrv.URL + "/c.pem"})
	body, _ := json.Marshal(map[string]any{"attest": "C", "origid": "abc", "iat": time.Now().Unix(), "orig": map[string]string{"tn": "14155550100"}, "dest": map[string][]string{"tn": {"15551212"}}})
	input := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(input))
	r, s, _ := ecdsa.Sign(rand.Reader, leafKey, sum[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	identity := input + "." + base64.RawURLEncoding.EncodeToString(sig) + ";info=<" + certSrv.URL + "/c.pem>;alg=ES256;ppt=shaken"

	raw := strings.Replace(cleanInvite("+14155550100", "Acme-SBC/1.0"), "Max-Forwards: 70\r\n", "Max-Forwards: 70\r\nIdentity: "+identity+"\r\n", 1)
	res := screen(t, srv, "198.51.100.20", raw)
	if res.Signals.Verstat != shaken.VerstatPassed || res.Signals.SignerSPC != "8181" || res.Signals.SignerName != "Gateway Eight LLC" {
		t.Fatalf("verification signals: %+v", res.Signals)
	}
	if res.Headers["X-Falcon-Verstat"] != shaken.VerstatPassed || res.Headers["X-Falcon-Signer"] != "8181" {
		t.Fatalf("headers: %+v", res.Headers)
	}
	codes := map[string]bool{}
	for _, rs := range res.Reasons {
		codes[rs.Code] = true
	}
	if !codes["shaken_attest_c"] || codes["shaken_verify_failed"] {
		t.Fatalf("reasons: %+v", res.Reasons)
	}

	events := waitEvents(t, db, 1)
	if events[0].Verstat != shaken.VerstatPassed || events[0].SignerSPC != "8181" || len(events[0].Shaken) == 0 {
		t.Fatalf("stored event: %+v", events[0])
	}
	full := do(t, srv, http.MethodGet, "/v1/events/"+itoa(events[0].ID), nil)
	if !strings.Contains(full.Body.String(), `"signature_ok":true`) || !strings.Contains(full.Body.String(), "Identity:") {
		t.Fatalf("event detail lacks verification or raw sip: %s", full.Body.String())
	}

	w := do(t, srv, http.MethodGet, "/v1/parties?by=signer&range=1h", nil)
	var parties struct {
		Data []store.Party `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &parties)
	if len(parties.Data) != 1 || parties.Data[0].Name != "8181" || parties.Data[0].Label != "Gateway Eight LLC" || parties.Data[0].AttestC != 1 || parties.Data[0].Passed != 1 {
		t.Fatalf("signer parties: %+v", parties.Data)
	}

	if w := do(t, srv, http.MethodPost, "/v1/rules", map[string]string{"kind": "deny", "subject": "spc", "value": "8181", "note": "gateway under traceback"}); w.Code != http.StatusCreated {
		t.Fatalf("spc deny: %d %s", w.Code, w.Body.String())
	}
	denied := screen(t, srv, "198.51.100.20", raw)
	if denied.Action != score.ActionReject || denied.Headers["X-Falcon-Block"] != "denylist" {
		t.Fatalf("signer deny did not reject: %+v", denied)
	}

	w = do(t, srv, http.MethodGet, "/v1/status", nil)
	if !strings.Contains(w.Body.String(), `"roots":1`) || !strings.Contains(w.Body.String(), `"cached_chains":1`) {
		t.Fatalf("status: %s", w.Body.String())
	}
}

func itoa(n int64) string {
	return big.NewInt(n).String()
}

func writeFile(path string, data []byte) error {
	return writeFileMode(path, data)
}
