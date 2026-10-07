package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

// Settings are the values an operator may change at runtime. Environment
// values are the defaults. A saved value wins until it is cleared.
type Settings struct {
	RetentionDays       int `json:"retention_days"`
	RawSIPRetentionDays int `json:"raw_sip_retention_days"`
	// ShareTelemetry sends redacted screening events to CallerAPI. The
	// environment default is on; a saved opt-out wins.
	ShareTelemetry bool `json:"share_telemetry"`
	FlagScore      int  `json:"flag_score"`
	ChallengeScore int  `json:"challenge_score"`
	RejectScore    int  `json:"reject_score"`
}

const (
	kvRetention    = "retention_days"
	kvRawRetention = "raw_sip_retention_days"
	kvShareOptOut  = "share_opt_out"
	kvFlagScore    = "threshold_flag"
	kvChallenge    = "threshold_challenge"
	kvRejectScore  = "threshold_reject"
	maxRetention   = 3650
	maxScore       = 101
)

func (s *Server) defaults() Settings {
	out := Settings{
		RetentionDays: s.Cfg.RetentionDays, RawSIPRetentionDays: s.Cfg.RawSIPRetentionDays, ShareTelemetry: s.Cfg.Share,
		FlagScore: s.Cfg.FlagScore, ChallengeScore: s.Cfg.ChallengeScore, RejectScore: s.Cfg.RejectScore,
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

// Settings returns the effective values.
func (s *Server) Settings(ctx context.Context) Settings {
	out := s.defaults()
	if s.Store == nil {
		return out
	}
	if v, _ := s.Store.KVGet(ctx, kvShareOptOut); v == "1" {
		out.ShareTelemetry = false
	}
	if v, _ := s.Store.KVGet(ctx, kvRetention); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			out.RetentionDays = n
		}
	}
	if v, _ := s.Store.KVGet(ctx, kvRawRetention); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			out.RawSIPRetentionDays = n
		}
	}
	if n, ok := kvInt(ctx, s, kvFlagScore); ok {
		out.FlagScore = n
	}
	if n, ok := kvInt(ctx, s, kvChallenge); ok {
		out.ChallengeScore = n
	}
	if n, ok := kvInt(ctx, s, kvRejectScore); ok {
		out.RejectScore = n
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

// LoadThresholds applies a dashboard save over the environment defaults.
func (s *Server) LoadThresholds(ctx context.Context) {
	if s == nil || s.Engine == nil || s.Store == nil {
		return
	}
	st := s.Settings(ctx)
	s.Engine.SetThresholds(score.Thresholds{Flag: st.FlagScore, Challenge: st.ChallengeScore, Reject: st.RejectScore})
}

// Sharing reports whether telemetry leaves this host right now.
func (s *Server) Sharing(ctx context.Context) bool {
	return s.Settings(ctx).ShareTelemetry
}

// Retention converts the effective settings for the janitor.
func (s *Server) Retention() store.Retention {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st := s.Settings(ctx)
	return store.Retention{
		Events: time.Duration(st.RetentionDays) * 24 * time.Hour,
		RawSIP: time.Duration(st.RawSIPRetentionDays) * 24 * time.Hour,
	}
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"effective":      s.Settings(r.Context()),
			"defaults":       s.defaults(),
			"limits":         map[string]int{"min_days": 1, "max_days": maxRetention},
			"raw_sip_stored": s.Cfg.StoreRawSIP,
		})
	case http.MethodPut, http.MethodPost:
		var body struct {
			RetentionDays       *int  `json:"retention_days"`
			RawSIPRetentionDays *int  `json:"raw_sip_retention_days"`
			ShareTelemetry      *bool `json:"share_telemetry"`
			FlagScore           *int  `json:"flag_score"`
			ChallengeScore      *int  `json:"challenge_score"`
			RejectScore         *int  `json:"reject_score"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		cur := s.Settings(r.Context())
		if body.RetentionDays != nil {
			cur.RetentionDays = *body.RetentionDays
		}
		if body.RawSIPRetentionDays != nil {
			cur.RawSIPRetentionDays = *body.RawSIPRetentionDays
		}
		if body.ShareTelemetry != nil {
			if *body.ShareTelemetry && !s.Cfg.Share {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "FALCON_SHARE=false in the environment; sharing cannot be turned on from the dashboard"})
				return
			}
			cur.ShareTelemetry = *body.ShareTelemetry
		}
		if body.FlagScore != nil {
			cur.FlagScore = *body.FlagScore
		}
		if body.ChallengeScore != nil {
			cur.ChallengeScore = *body.ChallengeScore
		}
		if body.RejectScore != nil {
			cur.RejectScore = *body.RejectScore
		}
		if cur.RetentionDays < 1 || cur.RetentionDays > maxRetention {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "retention_days must be between 1 and 3650"})
			return
		}
		if cur.RawSIPRetentionDays < 0 || cur.RawSIPRetentionDays > cur.RetentionDays {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "raw_sip_retention_days must be between 0 and retention_days"})
			return
		}
		if cur.FlagScore < 0 || cur.ChallengeScore < cur.FlagScore || cur.RejectScore < cur.ChallengeScore || cur.RejectScore > maxScore {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scores must satisfy 0 <= flag <= challenge <= reject <= 101"})
			return
		}
		if err := s.Store.KVSet(r.Context(), kvRetention, strconv.Itoa(cur.RetentionDays)); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if err := s.Store.KVSet(r.Context(), kvRawRetention, strconv.Itoa(cur.RawSIPRetentionDays)); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		optOut := "0"
		if !cur.ShareTelemetry {
			optOut = "1"
		}
		if err := s.Store.KVSet(r.Context(), kvShareOptOut, optOut); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		for _, kv := range []struct {
			key string
			n   int
		}{
			{kvFlagScore, cur.FlagScore},
			{kvChallenge, cur.ChallengeScore},
			{kvRejectScore, cur.RejectScore},
		} {
			if err := s.Store.KVSet(r.Context(), kv.key, strconv.Itoa(kv.n)); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
		}
		if s.Engine != nil {
			s.Engine.SetThresholds(score.Thresholds{Flag: cur.FlagScore, Challenge: cur.ChallengeScore, Reject: cur.RejectScore})
		}
		if b, err := json.Marshal(cur); err == nil {
			s.audit(r, "settings", "runtime", string(b))
		}
		writeJSON(w, http.StatusOK, map[string]any{"effective": cur})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or PUT"})
	}
}
