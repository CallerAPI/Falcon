package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/callerapi/falcon/internal/reputation"
	"github.com/callerapi/falcon/internal/shaken"
)

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
		"mode":       settings.Mode,
		"profile":    s.Cfg.Profile,
		"release":    s.currentRelease(),
		"fleet":      map[string]any{"hub": s.Cfg.FleetHub, "member": s.Cfg.FleetURL != ""},
		"listen":     s.Cfg.Listen,
		"started_at": s.StartedAt,
		"s3":         s.Cfg.S3Enabled(),
		"rules":      s.ruleIndex().Count(),
		"retention":  settings,
		"sip":        s.sipStatus(),
		"fas":        map[string]any{"mode": settings.FASMode, "hold_ms": s.Cfg.FASHold.Milliseconds(), "max_ringback_ms": s.Cfg.FASMaxRingback.Milliseconds()},
		"share": map[string]any{
			"configured": s.Cfg.Share,
			"effective":  s.Cfg.Share,
			"endpoint":   s.Cfg.CallerAPIBase + "/api/falcon/v1/telemetry",
			"credited":   s.Cfg.CallerAPIKey != "",
			"redacted":   []string{"called number", "called display name", "forwarding numbers", "PASSporT", "SDP body", "recordings", "transcripts"},
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
		"thresholds":     thresholdMap(s.Engine.Thresholds()),
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

func (s *Server) sipStatus() map[string]any {
	out := map[string]any{
		"enabled": s.Cfg.SIPEnabled(),
		"mode":    s.Cfg.SIPMode,
		"listen":  s.Cfg.SIPListen,
	}
	if s.Media != nil {
		out["active_calls"] = s.Media.Active()
		out["capacity"] = s.Media.Capacity()
	}
	return out
}

// handleConfig shows the effective configuration with secrets redacted.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Cfg.Redacted())
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
	if s.Media != nil {
		if err := s.Media.ReloadRoutes(ctx); err == nil {
			done["routes"] = true
		}
	}
	s.audit(r, "reload", "feeds", fmt.Sprint(done))
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": done})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	s.metrics.write(w, s)
}
