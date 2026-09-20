package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

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
}

const (
	kvRetention    = "retention_days"
	kvRawRetention = "raw_sip_retention_days"
	kvShareOptOut  = "share_opt_out"
	maxRetention   = 3650
)

func (s *Server) defaults() Settings {
	return Settings{RetentionDays: s.Cfg.RetentionDays, RawSIPRetentionDays: s.Cfg.RawSIPRetentionDays, ShareTelemetry: s.Cfg.Share}
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
	return out
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
		if cur.RetentionDays < 1 || cur.RetentionDays > maxRetention {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "retention_days must be between 1 and 3650"})
			return
		}
		if cur.RawSIPRetentionDays < 0 || cur.RawSIPRetentionDays > cur.RetentionDays {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "raw_sip_retention_days must be between 0 and retention_days"})
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
		if b, err := json.Marshal(cur); err == nil {
			s.audit(r, "settings", "runtime", string(b))
		}
		writeJSON(w, http.StatusOK, map[string]any{"effective": cur})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or PUT"})
	}
}
