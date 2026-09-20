package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/store"
)

// Value is what Falcon did for the operator over a window, computed from
// the store with no model involved. It is the first thing the assistant
// shows and the card at the top of the Overview, so the confirmation of
// value never depends on a key.
type Value struct {
	From              time.Time         `json:"from"`
	To                time.Time         `json:"to"`
	Screened          int               `json:"screened"`
	Blocked           int               `json:"blocked"`
	BlockedPct        float64           `json:"blocked_pct"`
	Held              int               `json:"held"`
	Outbound          int               `json:"outbound"`
	OutboundBlocked   int               `json:"outbound_blocked"`
	SpoofsStopped     int               `json:"spoofs_stopped"`
	VerifyFailed      int               `json:"verify_failed"`
	HoneypotHits      int               `json:"honeypot_hits"`
	RepeatRecordings  int               `json:"repeat_recordings"`
	VoiceScams        int               `json:"voice_scams"`
	SequentialDialers int               `json:"sequential_dialers"`
	CustomersFlagged  []string          `json:"customers_flagged"`
	TopReasons        []store.NameCount `json:"top_reasons"`
	TopSigners        []store.NameCount `json:"top_signers"`
	ByAction          map[string]int    `json:"by_action"`
	ByVerstat         map[string]int    `json:"by_verstat"`
	// MinutesNotCarried estimates talk time the platform did not pay for:
	// blocked calls times the average answered duration of allowed calls.
	MinutesNotCarried float64 `json:"minutes_not_carried"`
	AlertsFired       int     `json:"alerts_fired"`
	Sentence          string  `json:"sentence"`
}

// value computes the summary for a window.
func (s *Server) value(ctx context.Context, from, to time.Time) (Value, error) {
	v := Value{From: from, To: to, ByAction: map[string]int{}, ByVerstat: map[string]int{}, CustomersFlagged: []string{}}
	st, err := s.Store.Stats(ctx, from, to)
	if err != nil {
		return v, err
	}
	v.ByAction, v.ByVerstat = st.ByAction, st.ByVerstat
	v.TopReasons, v.TopSigners = st.TopReasons, st.TopSigners
	for _, n := range st.ByAction {
		v.Screened += n
	}
	v.Blocked = st.ByAction["reject"]
	v.Held = st.ByAction["flag"] + st.ByAction["challenge"]
	if v.Screened > 0 {
		v.BlockedPct = float64(v.Blocked) * 100 / float64(v.Screened)
	}
	v.VerifyFailed = st.ByVerstat["TN-Validation-Failed"]
	v.SpoofsStopped, _ = s.Store.CountReason(ctx, from, to, "caller_id_not_owned")
	v.HoneypotHits, _ = s.Store.CountReason(ctx, from, to, "honeypot_target")
	v.SequentialDialers, _ = s.Store.CountReason(ctx, from, to, "sequential_dialing")
	if parties, err := s.Store.Parties(ctx, "customer", from, to, 200); err == nil {
		for _, p := range parties {
			if p.Name == "" {
				continue
			}
			v.Outbound += p.Total
			v.OutboundBlocked += p.Reject
			if p.Total >= 10 && p.Reject*100/p.Total >= 30 {
				v.CustomersFlagged = append(v.CustomersFlagged, p.Name)
			}
		}
	}
	if samples, err := s.Store.VoiceSamples(ctx, 500); err == nil {
		for _, smp := range samples {
			if smp.At.Before(from) || smp.At.After(to) {
				continue
			}
			if smp.RepeatCount > 0 {
				v.RepeatRecordings++
			}
			if smp.Score >= 0.7 && smp.Category != "" && smp.Category != "none" {
				v.VoiceScams++
			}
		}
	}
	if alertsList, err := s.Store.Alerts(ctx, 500); err == nil {
		for _, a := range alertsList {
			if !a.At.Before(from) && !a.At.After(to) {
				v.AlertsFired++
			}
		}
	}
	// Average answered duration of allowed calls, when outcomes exist.
	if v.Blocked > 0 {
		if act, err := s.Store.WindowActivity(ctx, from); err == nil && act.Answered > 0 {
			v.MinutesNotCarried = float64(v.Blocked) * float64(act.TalkSeconds) / float64(act.Answered) / 60
		}
	}
	v.Sentence = v.sentence()
	return v, nil
}

func (v Value) sentence() string {
	if v.Screened == 0 {
		return "No calls screened in this window yet."
	}
	parts := []string{fmt.Sprintf("Falcon screened %d calls and blocked %d (%.1f%%)", v.Screened, v.Blocked, v.BlockedPct)}
	if v.SpoofsStopped > 0 {
		parts = append(parts, fmt.Sprintf("stopped %d spoofed caller ids leaving your own platform", v.SpoofsStopped))
	}
	if v.VerifyFailed > 0 {
		parts = append(parts, fmt.Sprintf("caught %d failed STIR/SHAKEN verifications", v.VerifyFailed))
	}
	if v.HoneypotHits > 0 {
		parts = append(parts, fmt.Sprintf("saw %d calls to unassigned numbers", v.HoneypotHits))
	}
	if v.RepeatRecordings > 0 {
		parts = append(parts, fmt.Sprintf("recognised %d replayed recordings", v.RepeatRecordings))
	}
	if v.VoiceScams > 0 {
		parts = append(parts, fmt.Sprintf("classified %d calls as scams from audio", v.VoiceScams))
	}
	if len(v.CustomersFlagged) > 0 {
		parts = append(parts, fmt.Sprintf("flagged %d of your customers for review", len(v.CustomersFlagged)))
	}
	return strings.Join(parts, "; ") + "."
}

func (s *Server) handleValue(w http.ResponseWriter, r *http.Request) {
	from, to := windowFrom(r)
	v, err := s.value(r.Context(), from, to)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// AssistantConfig names the chat model behind "Ask Falcon". Empty means
// the assistant answers with the value card and no prose.
type AssistantConfig struct {
	Provider string // "", "openai", "callerapi"
	BaseURL  string
	APIKey   string
	Model    string
	// CallerAPIBase and CallerAPIKey back the callerapi provider.
	CallerAPIBase string
	CallerAPIKey  string
	HTTP          *http.Client
}

const assistantSystem = `You are Falcon's assistant inside a telecom operator's own SIP risk engine. You answer questions about what Falcon saw and did on this install, using only the JSON context you are given. Be concrete: numbers first, then what they mean, then one action if one is warranted. Say which customers or signers to look at by their ids. If the context does not contain the answer, say so plainly. Never invent numbers. Short paragraphs, no bullet lists, no markdown headings. Keep under 180 words unless asked for detail.`

type assistantRequest struct {
	Question string `json:"question"`
	Range    string `json:"range"`
	History  []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"history"`
}

func (s *Server) handleAssistant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req assistantRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	q := r.URL.Query()
	if req.Range != "" {
		q.Set("range", req.Range)
		r.URL.RawQuery = q.Encode()
	}
	from, to := windowFrom(r)
	v, err := s.value(r.Context(), from, to)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Question) == "" || s.Assistant.Provider == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"answer":   v.Sentence,
			"value":    v,
			"provider": "none",
			"note":     "Set FALCON_ASSISTANT_PROVIDER to openai with your own key, or to callerapi with CALLERAPI_API_KEY, to ask questions. The value card needs no key.",
		})
		return
	}
	ctxJSON, _ := json.Marshal(map[string]any{
		"window":     map[string]any{"from": from, "to": to, "range": req.Range},
		"value":      v,
		"install_id": s.InstallID,
		"version":    Version,
	})
	messages := []map[string]string{{"role": "system", "content": assistantSystem + "\n\nContext JSON:\n" + string(ctxJSON)}}
	for _, h := range req.History {
		if h.Role == "user" || h.Role == "assistant" {
			messages = append(messages, map[string]string{"role": h.Role, "content": clipStr(h.Content, 4000)})
		}
	}
	messages = append(messages, map[string]string{"role": "user", "content": clipStr(req.Question, 4000)})

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	answer, err := s.Assistant.complete(ctx, messages)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "value": v})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"answer": answer, "value": v, "provider": s.Assistant.Provider + ":" + s.Assistant.Model})
}

func (a AssistantConfig) complete(ctx context.Context, messages []map[string]string) (string, error) {
	client := a.HTTP
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	var url string
	headers := map[string]string{"Content-Type": "application/json"}
	payload := map[string]any{"messages": messages, "temperature": 0.2, "max_tokens": 600}
	switch a.Provider {
	case "openai":
		url = strings.TrimRight(a.BaseURL, "/") + "/chat/completions"
		payload["model"] = a.Model
		if a.APIKey != "" {
			headers["Authorization"] = "Bearer " + a.APIKey
		}
	case "callerapi":
		url = strings.TrimRight(a.CallerAPIBase, "/") + "/api/voice/assistant"
		headers["X-Auth"] = a.CallerAPIKey
	default:
		return "", errors.New("assistant: no provider")
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("assistant %s: %s", resp.Status, clipStr(string(raw), 300))
	}
	// OpenAI shape, or CallerAPI's {"answer": "..."}.
	var out struct {
		Answer  string `json:"answer"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.Answer != "" {
		return out.Answer, nil
	}
	if len(out.Choices) > 0 {
		return strings.TrimSpace(out.Choices[0].Message.Content), nil
	}
	return "", errors.New("assistant: empty response")
}
