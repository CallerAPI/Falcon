package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/alerts"
	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/voice"
)

// Live voice verdicts.
//
// The CallerAPI live filter listens to a call as it happens: the switch
// forks the audio to wss://api.callerapi.com/api/voice/filter/stream and
// names this endpoint as the webhook. CallerAPI transcribes, runs the scam
// rules on every line, runs the model when the rules cannot phrase it, and
// posts an event the moment the score changes. Falcon never hears the
// audio. It receives the verdicts, ties them to the INVITE it screened,
// shows them in the dashboard, pages the operator, and blocks the next
// call from that number.
//
// Events, by X-Voice-Event: session.started, verdict, session.ended,
// session.error. Every body is signed: X-Voice-Signature is
// sha256=hex(hmac-sha256(body, account API key)). Falcon verifies with
// its own CALLERAPI_API_KEY. Without a key, the Falcon token is accepted
// instead so a self-hosted sender can post the same shape.

// LiveProvider marks a sample that came from the hosted live filter.
const LiveProvider = "callerapi-live"

// liveScamThreshold is the score at which a live verdict pages the
// operator. It matches the clip path.
const liveScamThreshold = 0.7

// maxVerdictBody bounds one webhook body. A session.ended event carries
// the transcript.
const maxVerdictBody = 1 << 20

type liveEvent struct {
	Type      string    `json:"type"`
	SessionID string    `json:"session_id"`
	Kind      string    `json:"kind"`
	CallID    string    `json:"call_id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	At        time.Time `json:"at"`
	Verdict   *struct {
		Score    float64  `json:"score"`
		Level    string   `json:"level"`
		Category string   `json:"category"`
		Tactics  []string `json:"tactics"`
		Signals  []string `json:"signals"`
		Summary  string   `json:"summary"`
		Source   string   `json:"source"`
	} `json:"verdict"`
	Transcript      string `json:"transcript"`
	DurationSeconds int    `json:"duration_seconds"`
	Reported        bool   `json:"reported"`
	Error           string `json:"error"`
}

// verdictSigned reports whether the body carries a valid HMAC for key.
func verdictSigned(r *http.Request, body []byte, key string) bool {
	if key == "" {
		return false
	}
	sig := strings.TrimSpace(r.Header.Get("X-Voice-Signature"))
	sig = strings.TrimPrefix(sig, "sha256=")
	if sig == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(sig)), []byte(want)) == 1
}

func (s *Server) handleVoiceVerdict(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxVerdictBody+1))
	if err != nil || len(body) > maxVerdictBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body too large"})
		return
	}
	if !verdictSigned(r, body, s.Cfg.CallerAPIKey) && !s.authenticated(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad signature"})
		return
	}
	var ev liveEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if ev.Type == "" {
		ev.Type = r.Header.Get("X-Voice-Event")
	}
	if ev.CallID == "" {
		ev.CallID = ev.SessionID
	}
	if ev.CallID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "call_id or session_id required"})
		return
	}

	sample, err := s.liveSample(r.Context(), ev)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.applyLiveEvent(r.Context(), &sample, ev)
	if err := s.Store.UpdateVoiceSample(r.Context(), sample); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if b, err := json.Marshal(map[string]any{"type": "voice", "live": true, "event_id": sample.EventID, "call_id": sample.CallID, "category": sample.Category, "score": sample.Score, "stage": ev.Type}); err == nil {
		s.hub.publish(b)
	}
	if ev.Type == "verdict" || ev.Type == "session.ended" {
		s.liveAlert(r.Context(), sample, ev)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"sample_id": sample.ID, "event_id": sample.EventID, "stage": ev.Type})
}

// liveSample finds or creates the one row a live session updates. The row
// is tied to the screened INVITE by Call-ID when there is one.
func (s *Server) liveSample(ctx context.Context, ev liveEvent) (store.VoiceSample, error) {
	if existing, ok, err := s.Store.VoiceSampleByCallID(ctx, ev.CallID); err == nil && ok && existing.Provider == LiveProvider {
		return existing, nil
	} else if err != nil {
		return store.VoiceSample{}, err
	}
	sample := store.VoiceSample{CallID: ev.CallID, Provider: LiveProvider, From: ev.From}
	if events, err := s.Store.Query(ctx, store.Filter{Q: ev.CallID, Limit: 5}); err == nil {
		for _, e := range events {
			if e.CallID == ev.CallID {
				sample.EventID = e.ID
				sample.Customer = e.Customer
				if sample.From == "" {
					sample.From = e.From
				}
				break
			}
		}
	}
	id, err := s.Store.AddVoiceSample(ctx, sample)
	if err != nil {
		return store.VoiceSample{}, err
	}
	sample.ID = id
	return sample, nil
}

// applyLiveEvent folds one event into the sample. A verdict only moves
// the stored score up: the operator sees the worst the call reached.
func (s *Server) applyLiveEvent(_ context.Context, sample *store.VoiceSample, ev liveEvent) {
	if ev.Verdict != nil && (ev.Verdict.Score >= sample.Score || sample.Category == "") {
		sample.Score = ev.Verdict.Score
		sample.Category = ev.Verdict.Category
		sample.Summary = ev.Verdict.Summary
		if len(ev.Verdict.Signals) > 0 {
			sample.Summary = strings.TrimSpace(sample.Summary + " Signals: " + strings.Join(ev.Verdict.Signals, "; "))
		}
	}
	if ev.Transcript != "" {
		sample.Transcript = ev.Transcript
	}
	if ev.DurationSeconds > 0 {
		sample.Seconds = float64(ev.DurationSeconds)
	}
	if ev.Type == "session.error" && ev.Error != "" {
		sample.Error = ev.Error
	}
}

// liveAlert pages once per number per hour when a live verdict crosses the
// scam threshold. The payload tells the operator's automation what to do:
// end the call on the switch, unassign the DID for an outbound customer,
// and review the account. Falcon itself cannot end the call.
func (s *Server) liveAlert(ctx context.Context, sample store.VoiceSample, ev liveEvent) {
	if s.Alerts == nil || ev.Verdict == nil {
		return
	}
	if !voice.IsScamCategory(ev.Verdict.Category) || ev.Verdict.Score < liveScamThreshold {
		return
	}
	who := sample.From
	if sample.Customer != "" {
		who = sample.Customer
	}
	direction := "inbound"
	if sample.EventID != 0 {
		if e, err := s.Store.Get(ctx, sample.EventID); err == nil && e.Direction != "" {
			direction = e.Direction
		}
	}
	action := "hangup_and_block_number"
	if direction == "outbound" {
		action = "hangup_unassign_did_and_review_customer"
	}
	s.Alerts.FireNow(ctx, alerts.Fired{
		Key: "voice_scam:" + who, Severity: "critical",
		Title:  fmt.Sprintf("Live scam call: %s (%s)", ev.Verdict.Category, sample.From),
		Detail: fmt.Sprintf("Score %.2f while the call is up. %s", ev.Verdict.Score, ev.Verdict.Summary),
		Data: map[string]any{
			"kind": "voice_scam", "live": true, "stage": ev.Type, "customer_id": sample.Customer, "calling_number": sample.From,
			"category": ev.Verdict.Category, "score": ev.Verdict.Score, "level": ev.Verdict.Level, "summary": ev.Verdict.Summary,
			"signals": ev.Verdict.Signals, "tactics": ev.Verdict.Tactics, "call_id": sample.CallID, "session_id": ev.SessionID,
			"event_id": sample.EventID, "sample_id": sample.ID, "direction": direction, "reported": ev.Reported,
			"suggested_action": action,
		},
	})
}
