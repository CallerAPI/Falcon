package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/callerapi/falcon/sdk"
	"github.com/coder/websocket"
)

const (
	kvAIVoiceScript = "ai_voice_script_id"
	kvAIVoiceToken  = "ai_voice_token"
)

var aiVoiceScriptID = regexp.MustCompile(`^[0-9]{1,12}$`)

func aiVoiceManifest() sdk.Manifest {
	return sdk.Manifest{
		Slug:    "ai-voice",
		Title:   "AI voice firewall",
		Kind:    "view",
		Surface: "native",
		Summary: "Scores ConnexCS transcripts on this install. The route script stays the screening app.",
	}
}

type aiVoiceState struct {
	mu        sync.Mutex
	live      bool
	scriptID  string
	token     string
	cancel    context.CancelFunc
	connected bool
	lastError string
	lastAt    time.Time
}

func (s *Server) startAIVoice(ctx context.Context) {
	if s.ai == nil {
		s.ai = &aiVoiceState{}
	}
	s.ai.live = true
	if s.Store == nil {
		return
	}
	scriptID, _ := s.Store.KVGet(ctx, kvAIVoiceScript)
	token, _ := s.Store.KVGet(ctx, kvAIVoiceToken)
	s.ai.apply(s, scriptID, token)
}

func (a *aiVoiceState) apply(s *Server, scriptID, token string) {
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	a.scriptID = strings.TrimSpace(scriptID)
	a.token = strings.TrimSpace(token)
	a.connected = false
	if a.scriptID == "" || a.token == "" {
		a.lastError = ""
		a.mu.Unlock()
		return
	}
	if !a.live {
		a.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	id, tok := a.scriptID, a.token
	a.mu.Unlock()
	go s.aiVoiceLoop(ctx, a, id, tok)
}

func (a *aiVoiceState) snapshot() (scriptID string, tokenSet, connected bool, lastError string, lastAt time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.scriptID, a.token != "", a.connected, a.lastError, a.lastAt
}

func (a *aiVoiceState) mark(connected bool, errText string, at time.Time) {
	a.mu.Lock()
	a.connected = connected
	if errText != "" {
		a.lastError = errText
	}
	if !at.IsZero() {
		a.lastAt = at
		a.lastError = ""
	}
	a.mu.Unlock()
}

func (s *Server) aiVoiceLoop(ctx context.Context, a *aiVoiceState, scriptID, token string) {
	url := "wss://app.connexcs.com/api/cp/scriptforge/" + scriptID
	for {
		if ctx.Err() != nil {
			return
		}
		err := s.aiVoiceSession(ctx, a, url, token)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			a.mark(false, err.Error(), time.Time{})
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (s *Server) aiVoiceSession(ctx context.Context, a *aiVoiceState, url, token string) error {
	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	conn, _, err := websocket.Dial(dialCtx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
	})
	cancel()
	if err != nil {
		return err
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(1 << 20)
	a.mark(true, "", time.Time{})
	for {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		s.acceptTranscript(msg)
		a.mark(true, "", time.Now().UTC())
	}
}

func (s *Server) acceptTranscript(body []byte) {
	line := readTranscript(body)
	text := line.Text
	if text == "" {
		text = line.Raw
	}
	if strings.TrimSpace(text) == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sample, err := s.saveTranscript(ctx, line, text)
	if err != nil {
		return
	}
	if line.Text != "" && s.Cfg.CallerAPIKey != "" && transcriptMarks.due(sample.CallID, line.Text, line.Final) {
		go s.scoreTranscript(sample, line)
	}
}

func (s *Server) handleAIVoice(w http.ResponseWriter, r *http.Request) {
	if s.ai == nil {
		s.ai = &aiVoiceState{}
	}
	switch r.Method {
	case http.MethodGet:
		scriptID, tokenSet, connected, lastError, lastAt := s.ai.snapshot()
		at := ""
		if !lastAt.IsZero() {
			at = lastAt.Format(time.RFC3339)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"script_id":  scriptID,
			"token_set":  tokenSet,
			"connected":  connected,
			"last_error": lastError,
			"last_at":    at,
		})
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		var in struct {
			ScriptID string `json:"script_id"`
			Token    string `json:"token"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		scriptID := strings.TrimSpace(in.ScriptID)
		if scriptID != "" && !aiVoiceScriptID.MatchString(scriptID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "script id is the number from the Script Forge URL"})
			return
		}
		token := strings.TrimSpace(in.Token)
		if token == "" {
			token, _ = s.Store.KVGet(r.Context(), kvAIVoiceToken)
		}
		if err := s.Store.KVSet(r.Context(), kvAIVoiceScript, scriptID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if err := s.Store.KVSet(r.Context(), kvAIVoiceToken, token); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.ai.apply(s, scriptID, token)
		scriptID, tokenSet, connected, lastError, lastAt := s.ai.snapshot()
		at := ""
		if !lastAt.IsZero() {
			at = lastAt.Format(time.RFC3339)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"script_id":  scriptID,
			"token_set":  tokenSet,
			"connected":  connected,
			"last_error": lastError,
			"last_at":    at,
		})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
	}
}
