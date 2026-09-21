// Package httpapi is the switch-facing API and the local dashboard.
//
// Every endpoint is one process, one SQLite file, no external service. The
// same handler set runs on a laptop and behind a load balancer on a fleet.
package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/callerapi/falcon/internal/alerts"
	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/feed"
	"github.com/callerapi/falcon/internal/fingerprint"
	"github.com/callerapi/falcon/internal/ipintel"
	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/reputation"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/shaken"
	"github.com/callerapi/falcon/internal/sipmsg"
	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/voice"
)

// MaxBody caps a screened SIP message. Configurable at start.
var MaxBody int64 = 64 * 1024

// Version is set by the build. The dashboard and /metrics show it.
var Version = "dev"

// Server is the switch-facing API and the local dashboard.
type Server struct {
	Cfg      config.Config
	Engine   *score.Engine
	Store    store.Store
	Feed     *feed.Spam
	Live     *feed.Live
	IPIntel  *ipintel.Table
	Verifier *shaken.Verifier
	// Reputation is the CallerAPI network feed; nil when off.
	Reputation *reputation.Table
	// Alerts is the webhook watcher; nil when not started.
	Alerts *alerts.Watcher
	// Sampler decides which calls get audio; VoiceProvider transcribes and
	// classifies the clips. Either may be nil.
	Sampler       *voice.Sampler
	VoiceProvider voice.Provider
	// VoiceReport asks the CallerAPI provider to file scam verdicts.
	VoiceReport bool
	// Assistant backs "Ask Falcon". Provider empty means value card only.
	Assistant AssistantConfig
	Trust     *shaken.TrustStore
	Web       fs.FS
	InstallID string
	StartedAt time.Time

	rulesMu sync.RWMutex
	rules   *lists.Index

	hub     *hub
	metrics *metrics
}

// Init prepares in-memory state. Call it once before Handler.
func (s *Server) Init(ctx context.Context) error {
	s.hub = newHub()
	s.metrics = newMetrics()
	if s.StartedAt.IsZero() {
		s.StartedAt = time.Now().UTC()
	}
	return s.ReloadRules(ctx)
}

// ReloadRules rebuilds the allow and deny index from the store.
func (s *Server) ReloadRules(ctx context.Context) error {
	if s.Store == nil {
		return nil
	}
	rules, err := s.Store.Rules(ctx)
	if err != nil {
		return err
	}
	idx := lists.NewIndex(rules, time.Now())
	s.rulesMu.Lock()
	s.rules = idx
	s.rulesMu.Unlock()
	return nil
}

func (s *Server) ruleIndex() *lists.Index {
	s.rulesMu.RLock()
	defer s.rulesMu.RUnlock()
	return s.rules
}

func (s *Server) Handler() http.Handler {
	if s.hub == nil {
		_ = s.Init(context.Background())
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.withAuth(s.handleMetrics))
	mux.HandleFunc("/v1/screen", s.withAuth(s.handleScreen))
	mux.HandleFunc("/v1/events", s.withAuth(s.handleEvents))
	mux.HandleFunc("/v1/events.csv", s.withAuth(s.handleEventsCSV))
	mux.HandleFunc("/v1/events/", s.withAuth(s.handleEvent))
	mux.HandleFunc("/v1/stats", s.withAuth(s.handleStats))
	mux.HandleFunc("/v1/histogram", s.withAuth(s.handleHistogram))
	mux.HandleFunc("/v1/parties", s.withAuth(s.handleParties))
	mux.HandleFunc("/v1/status", s.withAuth(s.handleStatus))
	mux.HandleFunc("/v1/config", s.withAuth(s.handleConfig))
	mux.HandleFunc("/v1/rules", s.withAuth(s.handleRules))
	mux.HandleFunc("/v1/rules/", s.withAuth(s.handleRule))
	mux.HandleFunc("/v1/stream", s.withAuth(s.handleStream))
	mux.HandleFunc("/v1/reload", s.withAuth(s.handleReload))
	mux.HandleFunc("/v1/demo", s.withAuth(s.handleDemo))
	mux.HandleFunc("/v1/settings", s.withAuth(s.handleSettings))
	mux.HandleFunc("/v1/audit", s.withAuth(s.handleAudit))
	mux.HandleFunc("/v1/alerts", s.withAuth(s.handleAlerts))
	mux.HandleFunc("/v1/alerts/settings", s.withAuth(s.handleAlertSettings))
	mux.HandleFunc("/v1/alerts/test", s.withAuth(s.handleAlertTest))
	mux.HandleFunc("/v1/traceback.zip", s.withAuth(s.handleTraceback))
	mux.HandleFunc("/v1/value", s.withAuth(s.handleValue))
	mux.HandleFunc("/v1/assistant", s.withAuth(s.handleAssistant))
	mux.HandleFunc("/v1/outcome", s.withAuth(s.handleOutcome))
	mux.HandleFunc("/v1/audio", s.withAuth(s.handleAudio))
	mux.HandleFunc("/v1/voice/samples", s.withAuth(s.handleVoiceSamples))
	// Signed by the CallerAPI account key, so it sits outside withAuth and
	// checks the HMAC itself. The Falcon token is accepted as a fallback.
	mux.HandleFunc("/v1/voice/verdict", s.handleVoiceVerdict)
	mux.HandleFunc("/v1/customers", s.withAuth(s.handleCustomers))
	mux.HandleFunc("/v1/customers/", s.withAuth(s.handleCustomer))

	if s.Web != nil {
		fileServer := http.FileServer(http.FS(s.Web))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" && !strings.Contains(r.URL.Path, ".") {
				r.URL.Path = "/"
			}
			if s.Cfg.DashboardPassword != "" && !s.dashboardOK(r) {
				w.Header().Set("WWW-Authenticate", `Basic realm="falcon"`)
				http.Error(w, "dashboard authentication required", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Cache-Control", "no-cache")
			fileServer.ServeHTTP(w, r)
		})
	}
	return securityHeaders(mux)
}

// securityHeaders is applied to every response. The dashboard has no inline
// scripts, so script-src is 'self'. Inline style attributes set bar widths,
// so style-src allows them. Nothing may frame the dashboard. No referrer
// leaves the host.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// isMutation reports whether a request changes state.
func isMutation(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// formCapable reports whether a content type is one an HTML form can send
// across origins without a CORS preflight. A browser attaches Basic
// credentials to such a submission on its own, so a mutation that arrives
// this way is refused whatever credentials it carries.
func formCapable(r *http.Request) bool {
	ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if ct == "" {
		return r.ContentLength != 0
	}
	return strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(ct, "multipart/form-data") ||
		strings.HasPrefix(ct, "text/plain")
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if isMutation(r) && formCapable(r) && r.URL.Path != "/v1/audio" {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "send application/json or application/sip"})
			return
		}
		if r.URL.Path == "/v1/audio" && r.Header.Get("X-Falcon-Token") == "" && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") && s.Cfg.Token != "" {
			// A clip upload is form-capable, so it must carry the token in
			// a header a cross-site form cannot set.
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "audio upload needs X-Falcon-Token"})
			return
		}
		next(w, r)
	}
}

// authenticated accepts the token in X-Falcon-Token or a Bearer header on
// any request, the token in the query on reads only (EventSource and
// download links cannot set headers), and the dashboard Basic credentials.
func (s *Server) authenticated(r *http.Request) bool {
	if s.Cfg.Token == "" {
		return true
	}
	got := strings.TrimSpace(r.Header.Get("X-Falcon-Token"))
	if got == "" {
		if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
			got = strings.TrimSpace(strings.TrimPrefix(ah, "Bearer "))
		}
	}
	if got == "" && !isMutation(r) {
		got = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	if got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.Cfg.Token)) == 1 {
		return true
	}
	return s.Cfg.DashboardPassword != "" && s.dashboardOK(r)
}

func (s *Server) dashboardOK(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	uOK := subtle.ConstantTimeCompare([]byte(user), []byte(s.Cfg.DashboardUser)) == 1
	pOK := subtle.ConstantTimeCompare([]byte(pass), []byte(s.Cfg.DashboardPassword)) == 1
	return uOK && pOK
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"version":    Version,
		"install_id": s.InstallID,
		"uptime_s":   int(time.Since(s.StartedAt).Seconds()),
	})
}

// ScreenRequest is one SIP request to score. Every transport builds one:
// the HTTP API from JSON or a raw body, the SIP listener from the wire.
type ScreenRequest struct {
	RawSIP     string `json:"raw_sip"`
	SourceIP   string `json:"source_ip"`
	SourcePort int    `json:"source_port"`
	Switch     string `json:"switch"`
	// Direction is "outbound" when the operator's own customer is
	// calling out; Customer names that account. Both optional.
	Direction  string            `json:"direction"`
	Customer   string            `json:"customer"`
	Method     string            `json:"method"`
	RequestURI string            `json:"request_uri"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

// ErrParse means the request was not a SIP message Falcon can read. The
// caller fails open.
var ErrParse = errors.New("parse sip")

func (s *Server) handleScreen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil {
		s.failOpen(w, "read body")
		return
	}
	if int64(len(raw)) > MaxBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "SIP message too large"})
		return
	}

	var req ScreenRequest
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") || looksJSON(raw) {
		if err := json.Unmarshal(raw, &req); err != nil {
			s.failOpen(w, "invalid json")
			return
		}
	} else {
		req.RawSIP = string(raw)
		req.SourceIP = r.Header.Get("X-Source-IP")
		req.Switch = r.Header.Get("X-Switch")
		req.Direction = r.Header.Get("X-Direction")
		req.Customer = r.Header.Get("X-Customer")
	}
	if req.SourceIP == "" {
		req.SourceIP = headerOr(r, "X-Source-IP", clientIP(r))
	}

	result, err := s.Screen(r.Context(), req)
	if err != nil {
		s.failOpen(w, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Screen scores one request, records the event, and fans out alerts and
// the live stream. The HTTP API and the SIP listener both end here.
func (s *Server) Screen(ctx context.Context, req ScreenRequest) (score.Result, error) {
	started := time.Now()
	msg, err := buildMessage(req)
	if err != nil {
		return score.Result{}, ErrParse
	}
	snap := sipmsg.SnapshotFrom(msg, req.SourceIP)
	en, verification := s.enrich(ctx, snap)
	en.Network = s.network(en, fingerprint.Compute(msg))
	s.behaviour(ctx, req, snap, &en)
	result := s.Engine.Score(snap, en)
	sample, trigger := s.Sampler.Decide(ctx, result, strings.TrimSpace(req.Customer))
	if sample {
		result.Sample = true
		result.Headers["X-Falcon-Sample"] = "1"
		result.Headers["X-Falcon-Sample-Seconds"] = strconv.Itoa(s.Sampler.Budget.ClipSeconds)
		result.Headers["X-Falcon-Sample-Reason"] = string(trigger)
	}

	ev := store.Event{
		ReceivedAt:  time.Now().UTC(),
		Action:      result.Action,
		RiskScore:   result.RiskScore,
		SourceIP:    snap.SourceIP,
		From:        result.Signals.From,
		To:          result.Signals.To,
		CallID:      snap.CallID,
		UserAgent:   snap.UserAgent,
		Attest:      snap.Identity.Attest,
		Verstat:     result.Signals.Verstat,
		SignerSPC:   result.Signals.SignerSPC,
		SignerName:  result.Signals.SignerName,
		Provider:    result.Signals.IPProvider,
		Fingerprint: fingerprint.Compute(msg),
		Reasons:     result.Reasons,
		Switch:      req.Switch,
		Direction:   en.Direction,
		Customer:    strings.TrimSpace(req.Customer),
		Honeypot:    en.Honeypot,
		Sampled:     result.Sample,
	}
	if s.Cfg.StoreRawSIP {
		ev.RawSIP = msg.Raw
	}
	if verification != nil {
		if b, err := json.Marshal(verification); err == nil {
			ev.Shaken = b
		}
	}
	s.metrics.observe(result, verification, time.Since(started))
	go s.spoofAlert(ev, result)
	go func(ev store.Event) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		id, err := s.Store.Insert(ctx, ev)
		if err != nil {
			log.Printf("falcon store: %v", err)
			return
		}
		ev.ID = id
		ev.RawSIP = ""
		if b, err := json.Marshal(ev); err == nil {
			s.hub.publish(b)
		}
	}(ev)

	return result, nil
}

// enrich gathers everything outside the SIP message: verification, operator
// rules, IP intel, and the paid CallerAPI signals.
func (s *Server) enrich(ctx context.Context, snap sipmsg.Snapshot) (score.Enrichment, *shaken.Result) {
	en := score.Enrichment{
		FeedEnabled: s.Cfg.FeedEnabled(),
		FirewallOn:  s.Cfg.FirewallEnabled(),
		FeedURL:     s.Cfg.UpsellFeedURL,
		FirewallURL: s.Cfg.UpsellFirewallURL,
	}
	var verification *shaken.Result
	if s.Verifier != nil && snap.Identity.Raw != "" {
		from := snap.PAIUser
		if from == "" {
			from = snap.FromUser
		}
		res := s.Verifier.Verify(ctx, snap.Identity.Raw, from, snap.ToUser)
		verification = &res
		en.Shaken = &score.Shaken{
			Verstat:    res.Verstat,
			Pending:    res.Pending,
			Revoked:    res.Revoked,
			SignerSPC:  res.Signer.SPC,
			SignerName: firstNonEmpty(res.Signer.Org, res.Signer.CN),
			Errors:     res.Errors,
		}
	}
	spc := ""
	if en.Shaken != nil {
		spc = en.Shaken.SignerSPC
	}
	if idx := s.ruleIndex(); idx != nil {
		if hit, ok := idx.Match(snap.FromUser, snap.SourceIP, spc); ok {
			en.List = &score.ListHit{Kind: string(hit.Kind), Subject: string(hit.Subject), Value: hit.Value, Note: hit.Note, RuleID: hit.ID}
		}
	}
	if s.IPIntel != nil && snap.SourceIP != "" {
		if m, ok := s.IPIntel.Lookup(snap.SourceIP); ok {
			en.IP = &score.IPIntel{Provider: m.Provider, Risk: string(m.Risk), Tags: m.Tags}
		}
	}
	if s.Feed != nil && s.Cfg.FeedEnabled() {
		en.FeedHit = s.Feed.Contains(snap.FromUser)
	}
	if s.Live != nil && s.Cfg.FirewallEnabled() && snap.FromUser != "" {
		ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
		if lu, err := s.Live.Lookup(ctx, snap.FromUser); err == nil {
			en.FirewallSpam = lu.IsSpam || lu.SpamScore >= 70
		}
	}
	return en, verification
}

// network reads the CallerAPI feed for the signer and the sending tool.
func (s *Server) network(en score.Enrichment, fp string) *score.Network {
	if s.Reputation == nil {
		return nil
	}
	var n score.Network
	n.Enforce = s.Cfg.ReputationEnforce
	if en.Shaken != nil {
		if sg, ok := s.Reputation.Signer(en.Shaken.SignerSPC); ok {
			n.SignerScore, n.SignerInstalls = sg.Score, sg.Installs
		}
	}
	if f, ok := s.Reputation.Fingerprint(fp); ok {
		n.FingerprintScore, n.FingerprintInstalls = f.Score, f.Installs
	}
	if n.SignerScore == 0 && n.FingerprintScore == 0 {
		return nil
	}
	return &n
}

func (s *Server) failOpen(w http.ResponseWriter, why string) {
	if !s.Cfg.FailOpen {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": why})
		return
	}
	writeJSON(w, http.StatusOK, score.Result{
		Action:    score.ActionAllow,
		RiskScore: 0,
		RiskBand:  "low",
		Reasons:   []score.Reason{{Code: "fail_open", Weight: 0, Detail: why, Category: "system"}},
		Headers:   map[string]string{"X-Falcon-Action": "allow", "X-Falcon-Score": "0"},
	})
}

func filterFrom(r *http.Request) store.Filter {
	q := r.URL.Query()
	from, to := parseRange(r)
	f := store.Filter{
		From:        from,
		To:          to,
		Action:      q.Get("action"),
		Verstat:     q.Get("verstat"),
		IP:          q.Get("ip"),
		SPC:         q.Get("spc"),
		Provider:    q.Get("provider"),
		Fingerprint: q.Get("fingerprint"),
		Direction:   q.Get("direction"),
		Customer:    q.Get("customer"),
		Number:      q.Get("number"),
		Q:           q.Get("q"),
	}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.BeforeID, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	return f
}

// parseRange reads range=15m|1h|6h|24h|7d|30d or from and to as RFC3339.
// Without either the window is the last 24 hours. Event lists with no
// range at all return every row, so an explicit empty window is honoured.
func parseRange(r *http.Request) (time.Time, time.Time) {
	q := r.URL.Query()
	// Upper bounds are exclusive and the store keeps whole seconds, so the
	// open end sits one second ahead to include the second in progress.
	now := time.Now().UTC().Add(time.Second)
	if v := q.Get("range"); v != "" {
		if d, ok := rangeDuration(v); ok {
			return now.Add(-d), now
		}
	}
	var from, to time.Time
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		}
	}
	return from, to
}

func rangeDuration(v string) (time.Duration, bool) {
	switch strings.ToLower(v) {
	case "15m":
		return 15 * time.Minute, true
	case "1h":
		return time.Hour, true
	case "6h":
		return 6 * time.Hour, true
	case "24h", "1d":
		return 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	case "30d":
		return 30 * 24 * time.Hour, true
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d, true
	}
	return 0, false
}

func windowFrom(r *http.Request) (time.Time, time.Time) {
	from, to := parseRange(r)
	now := time.Now().UTC().Add(time.Second)
	if to.IsZero() {
		to = now
	}
	if from.IsZero() {
		from = to.Add(-24 * time.Hour)
	}
	return from, to
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.Store.Query(r.Context(), filterFrom(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if events == nil {
		events = []store.Event{}
	}
	var next int64
	if n := len(events); n > 0 {
		next = events[n-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": events, "next_before": next})
}

func (s *Server) handleEventsCSV(w http.ResponseWriter, r *http.Request) {
	f := filterFrom(r)
	f.Limit = 500
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="falcon-events.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"received_at", "action", "risk_score", "from", "to", "source_ip", "provider", "attest", "verstat", "signer_spc", "signer_name", "user_agent", "call_id", "switch", "reasons"})
	written := 0
	for written < 50000 {
		events, err := s.Store.Query(r.Context(), f)
		if err != nil || len(events) == 0 {
			break
		}
		for _, ev := range events {
			codes := make([]string, 0, len(ev.Reasons))
			for _, rs := range ev.Reasons {
				codes = append(codes, rs.Code)
			}
			_ = cw.Write([]string{
				ev.ReceivedAt.UTC().Format(time.RFC3339), string(ev.Action), strconv.Itoa(ev.RiskScore), ev.From, ev.To,
				ev.SourceIP, ev.Provider, ev.Attest, ev.Verstat, ev.SignerSPC, ev.SignerName, ev.UserAgent, ev.CallID, ev.Switch,
				strings.Join(codes, "|"),
			})
			written++
		}
		f.BeforeID = events[len(events)-1].ID
		if len(events) < f.Limit {
			break
		}
	}
	cw.Flush()
}

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/v1/events/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	ev, err := s.Store.Get(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	// The event stays at the top level for the drawer; extras sit beside it.
	out := map[string]any{}
	if b, err := json.Marshal(ev); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	if ev.RawSIP != "" {
		if m, perr := sipmsg.Parse(ev.RawSIP); perr == nil {
			out["fingerprint_parts"] = fingerprint.Describe(m)
		}
	}
	if s.Reputation != nil {
		if sg, ok := s.Reputation.Signer(ev.SignerSPC); ok {
			out["network_signer"] = sg
		}
		if f, ok := s.Reputation.Fingerprint(ev.Fingerprint); ok {
			out["network_fingerprint"] = f
		}
	}
	if v, ok, err := s.Store.VoiceSampleForEvent(r.Context(), ev.ID); err == nil && ok {
		out["voice"] = v
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	from, to := windowFrom(r)
	st, err := s.Store.Stats(r.Context(), from, to)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleHistogram(w http.ResponseWriter, r *http.Request) {
	from, to := windowFrom(r)
	h, err := s.Store.Histogram(r.Context(), from, to)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"buckets":    h,
		"thresholds": map[string]int{"flag": s.Engine.Thresh.Flag, "challenge": s.Engine.Thresh.Challenge, "reject": s.Engine.Thresh.Reject},
		"from":       from,
		"to":         to,
	})
}

func (s *Server) handleParties(w http.ResponseWriter, r *http.Request) {
	from, to := windowFrom(r)
	by := r.URL.Query().Get("by")
	if by == "" {
		by = "signer"
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	parties, err := s.Store.Parties(r.Context(), by, from, to, limit)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if parties == nil {
		parties = []store.Party{}
	}
	if s.Reputation != nil {
		for i := range parties {
			switch by {
			case "signer":
				if sg, ok := s.Reputation.Signer(parties[i].Name); ok {
					parties[i].NetworkScore, parties[i].NetworkInstalls = sg.Score, sg.Installs
				}
			case "fingerprint":
				if f, ok := s.Reputation.Fingerprint(parties[i].Name); ok {
					parties[i].NetworkScore, parties[i].NetworkInstalls = f.Score, f.Installs
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"by": by, "data": parties, "from": from, "to": to})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	settings := s.Settings(r.Context())
	feedCount, feedAt, feedErr := 0, time.Time{}, ""
	if s.Feed != nil {
		feedCount, feedAt, feedErr = s.Feed.Status()
	}
	ipCount, ipAt, ipErr := 0, time.Time{}, ""
	if s.IPIntel != nil {
		ipCount, ipAt, ipErr = s.IPIntel.Status()
	}
	var trust shaken.Status
	var repStatus reputation.Status
	if s.Reputation != nil {
		repStatus = s.Reputation.Status()
	}
	certs, inflight := 0, 0
	if s.Trust != nil {
		trust = s.Trust.Status()
	}
	if s.Verifier != nil {
		certs, inflight = s.Verifier.CacheStats()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    Version,
		"install_id": s.InstallID,
		"listen":     s.Cfg.Listen,
		"started_at": s.StartedAt,
		"s3":         s.Cfg.S3Enabled(),
		"rules":      s.ruleIndex().Count(),
		"retention":  settings,
		"share": map[string]any{
			"configured": s.Cfg.Share,
			"effective":  settings.ShareTelemetry,
			"endpoint":   s.Cfg.CallerAPIBase + "/api/falcon/v1/telemetry",
			"credited":   s.Cfg.CallerAPIKey != "",
			"redacted":   []string{"called number", "called display name", "forwarding numbers", "PASSporT", "SDP body"},
		},
		"reputation": map[string]any{
			"configured": s.Cfg.Reputation && s.Cfg.Share,
			"enforce":    s.Cfg.ReputationEnforce,
			"status":     repStatus,
		},
		"voice": map[string]any{
			"provider": providerName(s.VoiceProvider),
			"budget":   s.voiceBudget(),
			"report":   s.VoiceReport,
		},
		"assistant": map[string]any{
			"provider": s.Assistant.Provider,
			"model":    s.Assistant.Model,
		},
		"raw_sip_stored": s.Cfg.StoreRawSIP,
		"thresholds":     map[string]int{"flag": s.Engine.Thresh.Flag, "challenge": s.Engine.Thresh.Challenge, "reject": s.Engine.Thresh.Reject},
		"spam_feed": map[string]any{
			"configured": s.Cfg.FeedEnabled() || (s.Cfg.Demo && s.Cfg.DemoProfile == "paid" && feedCount > 0),
			"count":      feedCount,
			"loaded_at":  feedAt,
			"error":      feedErr,
			"upsell_url": s.Cfg.UpsellFeedURL,
		},
		"demo": map[string]any{
			"enabled": s.Cfg.Demo,
			"profile": s.Cfg.DemoProfile,
		},
		"voice_firewall": map[string]any{
			"configured": s.Cfg.FirewallEnabled(),
			"upsell_url": s.Cfg.UpsellFirewallURL,
		},
		"ip_intel": map[string]any{
			"configured": s.Cfg.IPIntelEnabled(),
			"count":      ipCount,
			"loaded_at":  ipAt,
			"error":      ipErr,
			"file":       s.Cfg.IPIntelFile,
			"url":        s.Cfg.IPIntelSource(),
		},
		"shaken": map[string]any{
			"enabled":       s.Verifier != nil,
			"trust":         trust,
			"cached_chains": certs,
			"inflight":      inflight,
			"budget_ms":     s.Cfg.ShakenBudget.Milliseconds(),
		},
	})
}

// handleConfig shows the effective configuration with secrets redacted.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Cfg.Redacted())
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules, err := s.Store.Rules(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if rules == nil {
			rules = []lists.Rule{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": rules})
	case http.MethodPost:
		var body struct {
			Kind    string `json:"kind"`
			Subject string `json:"subject"`
			Value   string `json:"value"`
			Note    string `json:"note"`
			TTL     string `json:"ttl"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		rule := lists.Rule{Kind: lists.Kind(strings.ToLower(body.Kind)), Subject: lists.Subject(strings.ToLower(body.Subject)), Value: body.Value, Note: strings.TrimSpace(body.Note)}
		if body.TTL != "" {
			d, err := time.ParseDuration(body.TTL)
			if err != nil || d <= 0 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ttl must be a duration such as 24h"})
				return
			}
			rule.ExpiresAt = time.Now().UTC().Add(d)
		}
		saved, err := s.Store.AddRule(r.Context(), rule)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := s.ReloadRules(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.audit(r, "rule.add", fmt.Sprintf("%s %s %s", saved.Kind, saved.Subject, saved.Value), fmt.Sprintf("#%d %s", saved.ID, saved.Note))
		writeJSON(w, http.StatusCreated, saved)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST"})
	}
}

func (s *Server) handleRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "DELETE required"})
		return
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/v1/rules/"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := s.Store.DeleteRule(r.Context(), id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := s.ReloadRules(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "rule.delete", fmt.Sprintf("#%d", id), "")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// handleStream is server-sent events: one "event" message per screened
// request, plus a comment every 15 seconds to keep proxies awake.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "retry: 3000\n\n")
	flusher.Flush()

	ch, unsubscribe := s.hub.subscribe()
	defer unsubscribe()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			_, _ = fmt.Fprintf(w, "event: screen\ndata: %s\n\n", msg)
			flusher.Flush()
		case <-ping.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	done := map[string]bool{}
	if s.IPIntel != nil {
		s.IPIntel.Load(ctx)
		done["ip_intel"] = true
	}
	if s.Trust != nil && s.Trust.Enabled() {
		s.Trust.LoadRoots(ctx)
		s.Trust.LoadCRL(ctx)
		done["shaken_trust"] = true
	}
	if err := s.ReloadRules(ctx); err == nil {
		done["rules"] = true
	}
	s.audit(r, "reload", "feeds", fmt.Sprint(done))
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": done})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	s.metrics.write(w, s)
}

func buildMessage(req ScreenRequest) (*sipmsg.Message, error) {
	if strings.TrimSpace(req.RawSIP) != "" {
		return sipmsg.Parse(req.RawSIP)
	}
	var b strings.Builder
	method := req.Method
	if method == "" {
		method = "INVITE"
	}
	uri := req.RequestURI
	if uri == "" {
		uri = "sip:unknown@localhost"
	}
	b.WriteString(method)
	b.WriteByte(' ')
	b.WriteString(uri)
	b.WriteString(" SIP/2.0\n")
	for k, v := range req.Headers {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.WriteString(req.Body)
	return sipmsg.Parse(b.String())
}

func looksJSON(b []byte) bool {
	t := strings.TrimSpace(string(b))
	return strings.HasPrefix(t, "{")
}

func headerOr(r *http.Request, name, fallback string) string {
	if v := strings.TrimSpace(r.Header.Get(name)); v != "" {
		return v
	}
	return fallback
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
