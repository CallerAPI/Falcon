package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

// Settings are the values an operator may change at runtime. Environment
// values are the defaults. A saved value wins until it is cleared.
// Telemetry is not here: it follows FALCON_SHARE only.
type Settings struct {
	Mode                   string `json:"mode"`
	FASMode                string `json:"fas_mode"`
	FCCMode                string `json:"fcc_mode"`
	CLIWithhold            string `json:"cli_withhold"`
	RetentionDays          int    `json:"retention_days"`
	RawSIPRetentionDays    int    `json:"raw_sip_retention_days"`
	RecordingRetentionDays int    `json:"recording_retention_days"`
	BridgeFanoutEvery      int    `json:"bridge_fanout_every"`
	BridgeCleanEvery       int    `json:"bridge_clean_every"`
	BridgeCarry            string `json:"bridge_carry"`
	FlagScore              int    `json:"flag_score"`
	ChallengeScore         int    `json:"challenge_score"`
	RejectScore            int    `json:"reject_score"`
}

const (
	kvMode         = "mode"
	kvFASMode      = "fas_mode"
	kvFCCMode      = "fcc_mode"
	kvCLIWithhold  = "cli_withhold"
	kvRetention    = "retention_days"
	kvRawRetention = "raw_sip_retention_days"
	kvRecRetention = "recording_retention_days"
	kvFanoutEvery  = "bridge_fanout_every"
	kvCleanEvery   = "bridge_clean_every"
	kvBridgeCarry  = "bridge_carry"
	kvFlagScore    = "threshold_flag"
	kvChallenge    = "threshold_challenge"
	kvRejectScore  = "threshold_reject"
	maxRetention   = 3650
	maxScore       = 101
	settingsTTL    = 5 * time.Second
)

func (s *Server) defaults() Settings {
	out := Settings{
		Mode: s.Cfg.Mode, FASMode: s.Cfg.FASMode, FCCMode: s.Cfg.FCCMode, CLIWithhold: s.Cfg.CLIWithhold,
		RetentionDays: s.Cfg.RetentionDays, RawSIPRetentionDays: s.Cfg.RawSIPRetentionDays, RecordingRetentionDays: s.Cfg.RecordingRetentionDays,
		BridgeFanoutEvery: s.Cfg.BridgeFanoutEvery, BridgeCleanEvery: s.Cfg.BridgeCleanEvery, BridgeCarry: s.Cfg.BridgeCarry,
		FlagScore: s.Cfg.FlagScore, ChallengeScore: s.Cfg.ChallengeScore, RejectScore: s.Cfg.RejectScore,
	}
	if out.Mode == "" {
		out.Mode = config.ModeEnforce
	}
	if out.FASMode == "" {
		out.FASMode = config.FASMonitor
	}
	if out.FCCMode == "" {
		out.FCCMode = config.ModeMonitor
	}
	if out.CLIWithhold == "" {
		out.CLIWithhold = config.CLIOff
	}
	if out.BridgeCarry == "" {
		out.BridgeCarry = config.CarrySuspicious
	}
	if out.FlagScore == 0 && out.ChallengeScore == 0 && out.RejectScore == 0 && s.Engine != nil {
		th := s.Engine.Thresholds()
		out.FlagScore, out.ChallengeScore, out.RejectScore = th.Flag, th.Challenge, th.Reject
	}
	return out
}

func thresholdMap(t score.Thresholds) map[string]int {
	return map[string]int{"flag": t.Flag, "challenge": t.Challenge, "reject": t.Reject}
}

// Settings returns the effective values. They are cached for a few
// seconds because the SIP bridge reads them on every INVITE.
func (s *Server) Settings(ctx context.Context) Settings {
	s.settingsMu.Lock()
	if s.settings != nil && time.Since(s.settingsAt) < settingsTTL {
		out := *s.settings
		s.settingsMu.Unlock()
		return out
	}
	s.settingsMu.Unlock()
	out := s.loadSettings(ctx)
	s.settingsMu.Lock()
	s.settings, s.settingsAt = &out, time.Now()
	s.settingsMu.Unlock()
	return out
}

func (s *Server) forgetSettings() {
	s.settingsMu.Lock()
	s.settings = nil
	s.settingsMu.Unlock()
}

func (s *Server) loadSettings(ctx context.Context) Settings {
	out := s.defaults()
	if s.Store == nil {
		return out
	}
	if v, _ := s.Store.KVGet(ctx, kvMode); v == config.ModeEnforce || v == config.ModeMonitor {
		out.Mode = v
	}
	if v, _ := s.Store.KVGet(ctx, kvFASMode); v == config.FASOff || v == config.FASMonitor || v == config.FASEnforce {
		out.FASMode = v
	}
	if v, _ := s.Store.KVGet(ctx, kvFCCMode); v == config.ModeMonitor || v == config.ModeEnforce {
		out.FCCMode = v
	}
	if v, _ := s.Store.KVGet(ctx, kvCLIWithhold); v == config.CLIOff || v == config.CLIEnforce {
		out.CLIWithhold = v
	}
	if v, _ := s.Store.KVGet(ctx, kvBridgeCarry); v == config.CarrySuspicious || v == config.CarryAll {
		out.BridgeCarry = v
	}
	for _, kv := range []struct {
		key  string
		into *int
	}{
		{kvRetention, &out.RetentionDays},
		{kvRawRetention, &out.RawSIPRetentionDays},
		{kvRecRetention, &out.RecordingRetentionDays},
		{kvFanoutEvery, &out.BridgeFanoutEvery},
		{kvCleanEvery, &out.BridgeCleanEvery},
		{kvFlagScore, &out.FlagScore},
		{kvChallenge, &out.ChallengeScore},
		{kvRejectScore, &out.RejectScore},
	} {
		if n, ok := kvInt(ctx, s, kv.key); ok {
			*kv.into = n
		}
	}
	return out
}

func kvInt(ctx context.Context, s *Server, key string) (int, bool) {
	v, _ := s.Store.KVGet(ctx, key)
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	return n, err == nil
}

// Mode is enforce or monitor right now.
func (s *Server) Mode(ctx context.Context) string { return s.Settings(ctx).Mode }

// FASMode is off, monitor, or enforce right now.
func (s *Server) FASMode(ctx context.Context) string { return s.Settings(ctx).FASMode }

// FCCMode is monitor or enforce right now.
func (s *Server) FCCMode(ctx context.Context) string { return s.Settings(ctx).FCCMode }

// CLIWithhold is off or enforce right now.
func (s *Server) CLIWithhold(ctx context.Context) string { return s.Settings(ctx).CLIWithhold }

// CarryAll reports whether the bridge carries every call that is not a
// hard block.
func (s *Server) CarryAll(ctx context.Context) bool {
	return s.Settings(ctx).BridgeCarry == config.CarryAll
}

// Sampling is how often the bridge carries a fan-out call and a clean call.
func (s *Server) Sampling(ctx context.Context) (fanoutEvery, cleanEvery int) {
	st := s.Settings(ctx)
	return st.BridgeFanoutEvery, st.BridgeCleanEvery
}

// LoadThresholds applies a dashboard save over the environment defaults.
func (s *Server) LoadThresholds(ctx context.Context) {
	if s == nil || s.Engine == nil || s.Store == nil {
		return
	}
	st := s.Settings(ctx)
	s.Engine.SetThresholds(score.Thresholds{Flag: st.FlagScore, Challenge: st.ChallengeScore, Reject: st.RejectScore})
}

// Sharing reports whether telemetry leaves this host. It follows
// FALCON_SHARE only, so a dashboard click cannot turn it off.
func (s *Server) Sharing(context.Context) bool { return s.Cfg.Share }

// Retention converts the effective settings for the janitor.
func (s *Server) Retention() store.Retention {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st := s.Settings(ctx)
	return store.Retention{
		Events:        time.Duration(st.RetentionDays) * 24 * time.Hour,
		RawSIP:        time.Duration(st.RawSIPRetentionDays) * 24 * time.Hour,
		Recordings:    time.Duration(st.RecordingRetentionDays) * 24 * time.Hour,
		RecordingsDir: s.Cfg.RecordingsPath(),
	}
}

type settingsPatch struct {
	Mode                   *string `json:"mode"`
	FASMode                *string `json:"fas_mode"`
	FCCMode                *string `json:"fcc_mode"`
	CLIWithhold            *string `json:"cli_withhold"`
	RetentionDays          *int    `json:"retention_days"`
	RawSIPRetentionDays    *int    `json:"raw_sip_retention_days"`
	RecordingRetentionDays *int    `json:"recording_retention_days"`
	BridgeFanoutEvery      *int    `json:"bridge_fanout_every"`
	BridgeCleanEvery       *int    `json:"bridge_clean_every"`
	BridgeCarry            *string `json:"bridge_carry"`
	FlagScore              *int    `json:"flag_score"`
	ChallengeScore         *int    `json:"challenge_score"`
	RejectScore            *int    `json:"reject_score"`
}

func (p settingsPatch) apply(cur *Settings) {
	if p.Mode != nil {
		cur.Mode = *p.Mode
	}
	if p.FASMode != nil {
		cur.FASMode = *p.FASMode
	}
	if p.FCCMode != nil {
		cur.FCCMode = *p.FCCMode
	}
	if p.CLIWithhold != nil {
		cur.CLIWithhold = *p.CLIWithhold
	}
	if p.BridgeCarry != nil {
		cur.BridgeCarry = *p.BridgeCarry
	}
	for _, f := range []struct {
		in  *int
		out *int
	}{
		{p.RetentionDays, &cur.RetentionDays}, {p.RawSIPRetentionDays, &cur.RawSIPRetentionDays},
		{p.RecordingRetentionDays, &cur.RecordingRetentionDays}, {p.BridgeFanoutEvery, &cur.BridgeFanoutEvery},
		{p.BridgeCleanEvery, &cur.BridgeCleanEvery}, {p.FlagScore, &cur.FlagScore},
		{p.ChallengeScore, &cur.ChallengeScore}, {p.RejectScore, &cur.RejectScore},
	} {
		if f.in != nil {
			*f.out = *f.in
		}
	}
}

func validSettings(cur Settings) string {
	switch {
	case cur.Mode != config.ModeEnforce && cur.Mode != config.ModeMonitor:
		return "mode must be enforce or monitor"
	case cur.FASMode != config.FASOff && cur.FASMode != config.FASMonitor && cur.FASMode != config.FASEnforce:
		return "fas_mode must be off, monitor, or enforce"
	case cur.FCCMode != config.ModeMonitor && cur.FCCMode != config.ModeEnforce:
		return "fcc_mode must be monitor or enforce"
	case cur.CLIWithhold != config.CLIOff && cur.CLIWithhold != config.CLIEnforce:
		return "cli_withhold must be off or enforce"
	case cur.BridgeCarry != config.CarrySuspicious && cur.BridgeCarry != config.CarryAll:
		return "bridge_carry must be suspicious or all"
	case cur.RetentionDays < 1 || cur.RetentionDays > maxRetention:
		return "retention_days must be between 1 and 3650"
	case cur.RawSIPRetentionDays < 0 || cur.RawSIPRetentionDays > cur.RetentionDays:
		return "raw_sip_retention_days must be between 0 and retention_days"
	case cur.RecordingRetentionDays < 0 || cur.RecordingRetentionDays > maxRetention:
		return "recording_retention_days must be between 0 and 3650"
	case cur.BridgeFanoutEvery < 0 || cur.BridgeFanoutEvery > 100000 || cur.BridgeCleanEvery < 0 || cur.BridgeCleanEvery > 100000:
		return "bridge sampling must be between 0 and 100000"
	case cur.FlagScore < 0 || cur.ChallengeScore < cur.FlagScore || cur.RejectScore < cur.ChallengeScore || cur.RejectScore > maxScore:
		return "scores must satisfy 0 <= flag <= challenge <= reject <= 101"
	}
	return ""
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"effective":      s.Settings(r.Context()),
			"defaults":       s.defaults(),
			"limits":         map[string]int{"min_days": 1, "max_days": maxRetention},
			"raw_sip_stored": s.Cfg.StoreRawSIP,
			"share":          s.Cfg.Share,
		})
	case http.MethodPut, http.MethodPost:
		var patch settingsPatch
		if err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&patch); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		cur := s.loadSettings(r.Context())
		patch.apply(&cur)
		if msg := validSettings(cur); msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		pairs := map[string]string{
			kvMode: cur.Mode, kvFASMode: cur.FASMode, kvFCCMode: cur.FCCMode, kvCLIWithhold: cur.CLIWithhold,
			kvRetention: strconv.Itoa(cur.RetentionDays), kvRawRetention: strconv.Itoa(cur.RawSIPRetentionDays),
			kvRecRetention: strconv.Itoa(cur.RecordingRetentionDays),
			kvFanoutEvery:  strconv.Itoa(cur.BridgeFanoutEvery), kvCleanEvery: strconv.Itoa(cur.BridgeCleanEvery), kvBridgeCarry: cur.BridgeCarry,
			kvFlagScore: strconv.Itoa(cur.FlagScore), kvChallenge: strconv.Itoa(cur.ChallengeScore), kvRejectScore: strconv.Itoa(cur.RejectScore),
		}
		for k, v := range pairs {
			if err := s.Store.KVSet(r.Context(), k, v); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
		}
		s.forgetSettings()
		if s.Engine != nil {
			s.Engine.SetThresholds(score.Thresholds{Flag: cur.FlagScore, Challenge: cur.ChallengeScore, Reject: cur.RejectScore})
		}
		if b, err := json.Marshal(cur); err == nil {
			s.audit(r, "settings", "runtime", string(b))
		}
		if s.Compliance != nil && patch.FCCMode != nil {
			if err := s.Compliance.Evaluate(r.Context()); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "saved, but the FCC autopilot did not run: " + err.Error()})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"effective": cur})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or PUT"})
	}
}
