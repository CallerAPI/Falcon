// Package httpapi is the switch-facing API and the local dashboard.
//
// Every endpoint is one process, one SQLite file, no external service. The
// same handler set runs on a laptop and behind a load balancer on a fleet.
package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/callerapi/falcon/internal/alerts"
	"github.com/callerapi/falcon/internal/compliance"
	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/feed"
	"github.com/callerapi/falcon/internal/fleet"
	"github.com/callerapi/falcon/internal/ipintel"
	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/numbercheck"
	"github.com/callerapi/falcon/internal/reputation"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/shaken"
	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/update"
	"github.com/callerapi/falcon/internal/voice"
)

// MaxBody caps a screened SIP message. Configurable at start.
var MaxBody int64 = 64 * 1024

// Version is set by the build. The dashboard and /metrics show it.
var Version = "dev"

// MediaBridge is what the dashboard reads from the SIP bridge. Nil when
// the SIP listener does not bridge calls.
type MediaBridge interface {
	Active() int
	Capacity() int
	ReloadRoutes(ctx context.Context) error
}

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
	// Compliance is the FCC autopilot; nil when FALCON_FCC=false. The
	// upstream registry works without it.
	Compliance *compliance.Autopilot
	// Fleet is the cached caller counts from the other switches. Nil when
	// this process is not a fleet member.
	Fleet *fleet.Cache
	// NumberCheck keeps the operator's own numbers on CallerAPI and
	// rechecks them. Nil without a CallerAPI key.
	NumberCheck *numbercheck.Client
	// Media is the SIP bridge. Nil unless FALCON_SIP_MODE is bridge.
	Media MediaBridge
	// Release is the last public-version comparison.
	releaseMu sync.RWMutex
	release   update.Status
	// Sampler decides which calls get audio; VoiceProvider transcribes and
	// classifies the clips. Either may be nil.
	Sampler       *voice.Sampler
	VoiceProvider voice.Provider
	// VoiceReport asks the CallerAPI provider to file scam verdicts.
	VoiceReport bool
	// Assistant backs "Ask Falcon". Provider empty means no chat.
	Assistant AssistantConfig
	Trust     *shaken.TrustStore
	Web       fs.FS
	InstallID string
	StartedAt time.Time

	rulesMu sync.RWMutex
	rules   *lists.Index

	settingsMu sync.Mutex
	settings   *Settings
	settingsAt time.Time

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
	mux.HandleFunc("/v1/fleet/events", s.withAuth(s.handleFleetEvents))
	mux.HandleFunc("/v1/fleet/rules", s.withAuth(s.handleFleetRules))
	mux.HandleFunc("/v1/fleet/behaviour", s.withAuth(s.handleFleetBehaviour))
	mux.HandleFunc("/v1/screen", s.withAuth(s.handleScreen))
	mux.HandleFunc("/v1/overview", s.withAuth(s.handleOverview))
	mux.HandleFunc("/v1/insights/dismiss", s.withAuth(s.handleDismissInsight))
	mux.HandleFunc("/v1/events", s.withAuth(s.handleEvents))
	mux.HandleFunc("/v1/events.csv", s.withAuth(s.handleEventsCSV))
	mux.HandleFunc("/v1/events/", s.withAuth(s.handleEvent))
	mux.HandleFunc("/v1/recordings/", s.withAuth(s.handleRecording))
	mux.HandleFunc("/v1/stats", s.withAuth(s.handleStats))
	mux.HandleFunc("/v1/histogram", s.withAuth(s.handleHistogram))
	mux.HandleFunc("/v1/parties", s.withAuth(s.handleParties))
	mux.HandleFunc("/v1/suspects", s.withAuth(s.handleSuspects))
	mux.HandleFunc("/v1/vendors", s.withAuth(s.handleVendors))
	mux.HandleFunc("/v1/routes", s.withAuth(s.handleRoutes))
	mux.HandleFunc("/v1/routes/", s.withAuth(s.handleRoute))
	mux.HandleFunc("/v1/modules", s.withAuth(s.handleModules))
	mux.HandleFunc("/v1/numbercheck/", s.withAuth(s.handleNumberCheck))
	mux.HandleFunc("/v1/status", s.withAuth(s.handleStatus))
	mux.HandleFunc("/v1/config", s.withAuth(s.handleConfig))
	mux.HandleFunc("/v1/rules", s.withAuth(s.handleRules))
	mux.HandleFunc("/v1/rules/", s.withAuth(s.handleRule))
	mux.HandleFunc("/v1/upstreams", s.withAuth(s.handleUpstreams))
	mux.HandleFunc("/v1/upstreams/", s.withAuth(s.handleUpstream))
	mux.HandleFunc("/v1/upstreams/report", s.withAuth(s.handleUpstreamReport))
	mux.HandleFunc("/v1/upstreams/report.csv", s.withAuth(s.handleUpstreamReport))
	mux.HandleFunc("/v1/compliance", s.withAuth(s.handleCompliance))
	mux.HandleFunc("/v1/tracebacks", s.withAuth(s.handleTracebackCases))
	mux.HandleFunc("/v1/tracebacks/", s.withAuth(s.handleTracebackCase))
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
	mux.HandleFunc("/v1/voice/transcript", s.withAuth(s.handleVoiceTranscript))
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
// so style-src allows them. Recordings play from this origin. Nothing may
// frame the dashboard. No referrer leaves the host.
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self' blob:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Security-Policy", csp)
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

// uploadPath names the endpoints that take a file body.
func uploadPath(r *http.Request) bool {
	return r.URL.Path == "/v1/audio" || r.URL.Path == "/v1/numbercheck/import"
}

// crossSiteSafe reports whether the request carries a header a cross-site
// form cannot set. The dashboard sends X-Falcon-Request on every call.
func crossSiteSafe(r *http.Request) bool {
	return r.Header.Get("X-Falcon-Token") != "" || strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || r.Header.Get("X-Falcon-Request") != ""
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if isMutation(r) && formCapable(r) {
			if !uploadPath(r) {
				writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "send application/json or application/sip"})
				return
			}
			// A file post is form-capable, so a protected install needs a
			// header a cross-site form cannot set.
			if (s.Cfg.Token != "" || s.Cfg.DashboardPassword != "") && !crossSiteSafe(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "file upload needs X-Falcon-Token"})
				return
			}
		}
		next(w, r)
	}
}

// credential reads the token from X-Falcon-Token or a Bearer header on any
// request, and from the query on reads only: EventSource, download links,
// and the audio player cannot set headers.
func (s *Server) credential(r *http.Request) string {
	got := strings.TrimSpace(r.Header.Get("X-Falcon-Token"))
	if got == "" {
		if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
			got = strings.TrimSpace(strings.TrimPrefix(ah, "Bearer "))
		}
	}
	if got == "" && !isMutation(r) {
		got = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	return got
}

func tokenMatch(got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Server) authenticated(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/v1/fleet/") {
		return s.Cfg.FleetHub && tokenMatch(s.credential(r), s.Cfg.FleetToken)
	}
	if s.Cfg.Token == "" && s.Cfg.MetricsToken == "" {
		return true
	}
	got := s.credential(r)
	if r.URL.Path == "/metrics" && tokenMatch(got, s.Cfg.MetricsToken) {
		return true
	}
	if s.Cfg.Token == "" {
		return s.Cfg.DashboardPassword != "" && s.dashboardOK(r)
	}
	if tokenMatch(got, s.Cfg.Token) {
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
