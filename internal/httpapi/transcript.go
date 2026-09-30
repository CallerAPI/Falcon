package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/voice"
)

const transcriptProvider = "connexcs"

// transcriptLine is the text Falcon could find in one bus message.
// ConnexCS does not document the payload, so several names are tried.
type transcriptLine struct {
	CallID string
	From   string
	To     string
	Text   string
	Final  bool
	Raw    string
}

func readTranscript(body []byte) transcriptLine {
	raw := strings.TrimSpace(string(body))
	line := transcriptLine{Raw: raw}
	var msg any
	if json.Unmarshal(body, &msg) != nil {
		line.Text = raw
		return line
	}
	obj := unwrapTranscript(msg)
	line.CallID = firstString(obj, "callid", "call_id", "callId", "Call-ID")
	line.From = firstString(obj, "cli", "from", "caller", "source")
	line.To = firstString(obj, "dest_number", "destination", "dest", "to")
	line.Text = firstString(obj, "text", "transcript", "transcription", "result")
	line.Final = firstBool(obj, "final", "is_final", "isFinal", "done")
	return line
}

func unwrapTranscript(msg any) map[string]any {
	obj, ok := msg.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	for _, key := range []string{"data", "message", "payload"} {
		inner, ok := obj[key].(map[string]any)
		if ok && firstString(inner, "text", "transcript", "transcription", "callid", "call_id") != "" {
			return inner
		}
	}
	return obj
}

func firstString(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		switch v := obj[key].(type) {
		case string:
			if s := strings.TrimSpace(v); s != "" {
				return s
			}
		}
	}
	return ""
}

func firstBool(obj map[string]any, keys ...string) bool {
	for _, key := range keys {
		switch v := obj[key].(type) {
		case bool:
			if v {
				return true
			}
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "1", "true", "yes", "final":
				return true
			}
		}
	}
	return false
}

var transcriptMarks transcriptScore

type transcriptScore struct {
	mu   sync.Mutex
	last map[string]transcriptMark
}

type transcriptMark struct {
	at int64
	n  int
}

func (t *transcriptScore) due(callID, text string, final bool) bool {
	if strings.TrimSpace(text) == "" || callID == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.last == nil {
		t.last = map[string]transcriptMark{}
	}
	prev := t.last[callID]
	now := time.Now().Unix()
	if !final && now-prev.at < 30 && len(text)-prev.n < 80 {
		return false
	}
	t.last[callID] = transcriptMark{at: now, n: len(text)}
	return true
}

func (s *Server) handleVoiceTranscript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxVerdictBody+1))
	if err != nil || len(body) > maxVerdictBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body too large"})
		return
	}
	line := readTranscript(body)
	text := line.Text
	if text == "" {
		text = line.Raw
	}
	if strings.TrimSpace(text) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty transcript"})
		return
	}
	ctx := r.Context()
	sample, err := s.saveTranscript(ctx, line, text)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if line.Text != "" && s.Cfg.CallerAPIKey != "" && transcriptMarks.due(sample.CallID, line.Text, line.Final) {
		go s.scoreTranscript(sample, line)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"saved": true, "sample_id": sample.ID, "event_id": sample.EventID, "scored": line.Text != "" && s.Cfg.CallerAPIKey != ""})
}

func (s *Server) saveTranscript(ctx context.Context, line transcriptLine, text string) (store.VoiceSample, error) {
	callID := line.CallID
	if callID == "" {
		callID = "transcript"
	}
	var eventID int64
	if line.CallID != "" {
		if events, err := s.Store.Query(ctx, store.Filter{Q: line.CallID, Limit: 5}); err == nil {
			for _, ev := range events {
				if ev.CallID == line.CallID {
					eventID = ev.ID
					break
				}
			}
		}
	}
	if existing, ok, err := s.Store.VoiceSampleByCallID(ctx, callID); err != nil {
		return store.VoiceSample{}, err
	} else if ok {
		if eventID != 0 {
			existing.EventID = eventID
		}
		existing.Transcript = text
		if line.From != "" {
			existing.From = line.From
		}
		existing.Provider = transcriptProvider
		if err := s.Store.UpdateVoiceSample(ctx, existing); err != nil {
			return store.VoiceSample{}, err
		}
		return existing, nil
	}
	sample := store.VoiceSample{
		EventID:    eventID,
		CallID:     callID,
		Transcript: text,
		From:       line.From,
		Provider:   transcriptProvider,
	}
	id, err := s.Store.AddVoiceSample(ctx, sample)
	if err != nil {
		return store.VoiceSample{}, err
	}
	sample.ID = id
	return sample, nil
}

func (s *Server) scoreTranscript(sample store.VoiceSample, line transcriptLine) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	verdict, err := scoreCallerAPIText(ctx, s.Cfg.CallerAPIBase, s.Cfg.CallerAPIKey, line.Text, line.From, line.To)
	if err != nil {
		log.Printf("falcon transcript score: %v", err)
		sample.Error = err.Error()
		_ = s.Store.UpdateVoiceSample(ctx, sample)
		return
	}
	sample.Category = verdict.Category
	sample.Score = verdict.Score
	sample.Summary = verdict.Summary
	sample.Error = ""
	sample.Provider = transcriptProvider
	if err := s.Store.UpdateVoiceSample(ctx, sample); err != nil {
		log.Printf("falcon transcript store: %v", err)
		return
	}
	if voice.IsScamCategory(verdict.Category) && verdict.Score >= liveScamThreshold && sample.EventID != 0 {
		if err := s.Store.NoteVoiceScam(ctx, sample.EventID, verdict.Category, verdict.Score, verdict.Summary); err != nil {
			log.Printf("falcon transcript reason: %v", err)
		}
	}
	if b, err := json.Marshal(map[string]any{"type": "voice", "event_id": sample.EventID, "call_id": sample.CallID, "category": sample.Category, "score": sample.Score}); err == nil {
		s.hub.publish(b)
	}
}

func scoreCallerAPIText(ctx context.Context, base, key, text, from, to string) (voice.Verdict, error) {
	payload, _ := json.Marshal(map[string]any{
		"transcript": text,
		"from":       from,
		"to":         to,
		"report":     false,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/api/voice/scan", bytes.NewReader(payload))
	if err != nil {
		return voice.Verdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth", key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return voice.Verdict{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return voice.Verdict{}, errStatus(resp.Status)
	}
	var out struct {
		Verdict struct {
			Score    float64 `json:"score"`
			Category string  `json:"category"`
			Summary  string  `json:"summary"`
		} `json:"verdict"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return voice.Verdict{}, err
	}
	return voice.Verdict{Category: out.Verdict.Category, Score: out.Verdict.Score, Summary: out.Verdict.Summary, Provider: transcriptProvider}, nil
}

type errStatus string

func (e errStatus) Error() string { return string(e) }
