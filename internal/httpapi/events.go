package httpapi

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/fingerprint"
	"github.com/callerapi/falcon/internal/sipmsg"
	"github.com/callerapi/falcon/internal/store"
)

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
		Verdict:     q.Get("verdict"),
		Recorded:    truthy(q.Get("recorded")),
		FAS:         truthy(q.Get("fas")),
		Bridged:     truthy(q.Get("bridged")),
	}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.BeforeID, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	return f
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
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
	_ = cw.Write([]string{"received_at", "action", "risk_score", "from", "to", "source_ip", "provider", "attest", "verstat", "signer_spc", "signer_name", "user_agent", "call_id", "switch", "latency_ms", "reasons"})
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
				strconv.FormatFloat(float64(ev.LatencyUS)/1000, 'f', 2, 64), strings.Join(codes, "|"),
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
	if v, ok := s.voiceForEvent(r.Context(), ev); ok {
		out["voice"] = v
		if v.HasAudio() {
			out["recording_url"] = "/v1/recordings/" + strconv.FormatInt(v.ID, 10) + ".wav"
		}
	}
	if m, ok, err := s.Store.MediaCallByCallID(r.Context(), ev.CallID); err == nil && ok {
		out["media"] = m
		if _, has := out["recording_url"]; !has && m.Recording != "" {
			out["recording_url"] = "/v1/recordings/call-" + strconv.FormatInt(m.ID, 10) + ".wav"
		}
	}
	out["why"] = explain(ev.Reasons)
	out["listen"] = map[string]any{
		"bridge":   s.Media != nil,
		"clips":    s.Sampler != nil && s.Sampler.Enabled,
		"provider": providerName(s.VoiceProvider),
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
		"thresholds": thresholdMap(s.Engine.Thresholds()),
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

func (s *Server) handleSuspects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
		return
	}
	from, to := windowFrom(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.Store.Suspects(r.Context(), from, to, r.URL.Query().Get("direction"), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows, "from": from, "to": to})
}

// handleVendors is answer quality per route: false answers and the billed
// seconds they added. The default path, back to the switch, is "".
func (s *Server) handleVendors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
		return
	}
	from, to := windowFrom(r)
	rows, err := s.Store.RouteStats(r.Context(), from, to)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows, "from": from, "to": to, "fas_mode": s.FASMode(r.Context())})
}
