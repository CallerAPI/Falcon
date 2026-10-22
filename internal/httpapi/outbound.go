package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/alerts"
	"github.com/callerapi/falcon/internal/media"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/sipmsg"
	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/voice"
)

// MaxClipBytes caps an uploaded recording. 8 kHz mono 16-bit is about
// half an hour at this size. The scan is sent in short pieces.
const MaxClipBytes = 32 << 20

// behaviour fills the direction, customer, honeypot, and caller activity
// parts of the enrichment. All of it comes from this install's own store.
func (s *Server) behaviour(ctx context.Context, req ScreenRequest, snap sipmsg.Snapshot, en *score.Enrichment) {
	en.Direction, en.Customer = s.direction(ctx, req, snap)
	if idx := s.ruleIndex(); idx != nil && snap.ToUser != "" {
		en.Honeypot = idx.IsHoneypot(snap.ToUser)
	}
	if snap.FromUser != "" {
		a, err := s.Store.CallerActivity(ctx, snap.FromUser, time.Now().Add(-time.Hour))
		if err != nil {
			a = store.Activity{}
		}
		if s.Fleet != nil {
			a = s.Fleet.Merge(snap.FromUser, a)
		}
		if a.Calls > 0 {
			lim := score.DefaultBehaviour(s.Engine.Limits)
			en.Caller = &score.Behaviour{
				Calls: a.Calls, DistinctCallees: a.DistinctCallees, Completed: a.Completed, Answered: a.Answered,
				TalkSeconds: a.TalkSeconds, Sequential: a.Sequential(lim.SequentialN), HoneypotHits: a.HoneypotHits,
			}
		}
	}
}

// direction decides inbound or outbound for one call with no setup. What
// the switch says wins. A named customer means outbound. Otherwise a
// calling number that one of your customers owns is outbound. Anything
// else is inbound.
func (s *Server) direction(ctx context.Context, req ScreenRequest, snap sipmsg.Snapshot) (string, *score.CustomerCtx) {
	said := strings.ToLower(strings.TrimSpace(req.Direction))
	if id := strings.TrimSpace(req.Customer); id != "" {
		cc := &score.CustomerCtx{ID: id}
		if c, ok, err := s.Store.Customer(ctx, id); err == nil && ok {
			cc.Known = true
			cc.HasDIDs = len(c.DIDs) > 0
			cc.OwnsCaller = c.Owns(snap.FromUser)
		}
		if said != "inbound" {
			said = "outbound"
		}
		return said, cc
	}
	if said == "inbound" || said == "outbound" {
		return said, nil
	}
	for _, c := range s.customerList(ctx) {
		if c.Owns(snap.FromUser) {
			return "outbound", &score.CustomerCtx{ID: c.ID, Known: true, HasDIDs: true, OwnsCaller: true}
		}
	}
	return "inbound", nil
}

// customerList is cached for a few seconds because every INVITE reads it.
func (s *Server) customerList(ctx context.Context) []store.Customer {
	s.customersMu.Lock()
	defer s.customersMu.Unlock()
	if s.customers != nil && time.Since(s.customersAt) < settingsTTL {
		return s.customers
	}
	list, err := s.Store.Customers(ctx)
	if err != nil {
		return s.customers
	}
	s.customers, s.customersAt = list, time.Now()
	return list
}

func (s *Server) forgetCustomers() {
	s.customersMu.Lock()
	s.customers = nil
	s.customersMu.Unlock()
}

// spoofAlert pages the operator the moment one of their own customers
// presents a number it does not own. This is the finding a regulator
// fines for; it should not wait for a dashboard visit.
func (s *Server) spoofAlert(ev store.Event, res score.Result) {
	if s.Alerts == nil || res.Headers["X-Falcon-Block"] != "caller_id" || ev.Customer == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var dids []string
	if c, ok, err := s.Store.Customer(ctx, ev.Customer); err == nil && ok {
		dids = c.DIDs
	}
	s.Alerts.FireNow(ctx, alerts.Fired{
		Key:      "spoof:" + ev.Customer,
		Severity: "critical",
		Title:    fmt.Sprintf("Customer %s presented a caller id it does not own", ev.Customer),
		Detail:   fmt.Sprintf("Outbound call from %s was rejected: the number is not in the customer's list. Review the account and the trunk it came from.", ev.From),
		Data: map[string]any{
			"kind": "outbound_spoof", "customer_id": ev.Customer, "calling_number": ev.From,
			"customer_dids": dids, "source_ip": ev.SourceIP, "call_id": ev.CallID, "event_id": ev.ID,
			"suggested_action": "suspend_outbound_and_review",
		},
	})
}

// handleOutcome records how a call ended. Adapters post it at hangup.
func (s *Server) handleOutcome(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var body struct {
		CallID      string `json:"call_id"`
		Answered    bool   `json:"answered"`
		DurationS   int    `json:"duration_s"`
		HangupCause string `json:"hangup_cause"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil || strings.TrimSpace(body.CallID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "call_id required"})
		return
	}
	if body.DurationS < 0 {
		body.DurationS = 0
	}
	ev, err := s.Store.SetOutcome(r.Context(), strings.TrimSpace(body.CallID), store.Outcome{Answered: body.Answered, DurationS: body.DurationS, HangupCause: clipStr(body.HangupCause, 64)})
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	s.metrics.outcome(body.Answered, body.DurationS)
	writeJSON(w, http.StatusOK, map[string]any{"event_id": ev.ID, "answered": body.Answered, "duration_s": body.DurationS})
}

// handleAudio stores a recording and transcribes the whole file.
// Local analysis is synchronous and free; the provider runs after the
// response, within the clip budget already spent by the sampler.
func (s *Server) handleAudio(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	callID := strings.TrimSpace(r.URL.Query().Get("call_id"))
	if callID == "" {
		callID = strings.TrimSpace(r.Header.Get("X-Call-Id"))
	}
	if callID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "call_id query parameter required"})
		return
	}
	var wav []byte
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(MaxClipBytes); err != nil {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "clip too large"})
			return
		}
		f, _, err := r.FormFile("audio")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "multipart field audio required"})
			return
		}
		defer f.Close()
		wav, _ = io.ReadAll(io.LimitReader(f, MaxClipBytes+1))
	} else {
		wav, _ = io.ReadAll(io.LimitReader(r.Body, MaxClipBytes+1))
	}
	if len(wav) > MaxClipBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "clip too large"})
		return
	}
	if _, err := voice.DecodeWAV(wav); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ev, ok, err := s.Store.EventByCallID(r.Context(), callID)
	if err != nil || !ok || ev.ID == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no event with that call id"})
		return
	}
	// The clip is kept so the operator can listen to it. A host that
	// cannot write the folder still analyses the clip.
	rel := media.RecordingName(time.Now(), callID)
	if err := writeRecording(s.Cfg.RecordingsPath(), rel, wav); err != nil {
		log.Printf("falcon voice: keep clip: %v", err)
		rel = ""
	}
	sample, f, err := s.ingestAudio(r.Context(), wav, rel, ev, callID, ev.From, true)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"sample_id": sample.ID, "features": f, "repeat_count": sample.RepeatCount,
		"provider": providerName(s.VoiceProvider), "classification": s.VoiceProvider != nil,
	})
}

func writeRecording(dir, rel string, wav []byte) error {
	path, ok := store.RecordingPath(dir, rel)
	if !ok {
		return fmt.Errorf("bad recording path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, wav, 0o640)
}

func providerName(p voice.Provider) string {
	if p == nil {
		return "off"
	}
	return p.Name()
}

// classifyClip runs the provider and stores what it said. The transcript
// stays in this database; it is never shared.
func (s *Server) classifyClip(sample store.VoiceSample, ev store.Event, wav []byte, f voice.Features) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	from := firstNonEmpty(ev.From, sample.From)
	v, err := s.VoiceProvider.Analyse(ctx, wav, voice.Meta{From: from, Customer: ev.Customer, CallID: sample.CallID, Report: s.VoiceReport})
	sample.Provider = providerName(s.VoiceProvider)
	if err != nil {
		sample.Error = err.Error()
		log.Printf("falcon voice: %s: %v", sample.Provider, err)
	} else {
		sample.Transcript, sample.Category, sample.Score, sample.Summary = v.Transcript, v.Category, v.Score, v.Summary
		if len(v.Turns) > 0 {
			if b, err := json.Marshal(v.Turns); err == nil {
				sample.Turns = b
			}
		}
	}
	if err := s.Store.UpdateVoiceSample(ctx, sample); err != nil {
		log.Printf("falcon voice store: %v", err)
	}
	if b, err := json.Marshal(map[string]any{"type": "voice", "event_id": ev.ID, "category": sample.Category, "score": sample.Score}); err == nil {
		s.hub.publish(b)
	}
	if sample.Error == "" && voice.IsScamCategory(sample.Category) && sample.Score >= 0.7 {
		if err := s.Store.NoteVoiceScam(ctx, ev.ID, sample.Category, sample.Score, sample.Summary); err != nil {
			log.Printf("falcon voice reason: %v", err)
		}
	}
	if sample.Error == "" && voice.IsScamCategory(sample.Category) && sample.Score >= 0.7 && s.Alerts != nil {
		who := ev.From
		if ev.Customer != "" {
			who = ev.Customer
		}
		s.Alerts.FireNow(ctx, alerts.Fired{
			Key: "voice_scam:" + who, Severity: "critical",
			Title:  fmt.Sprintf("Scam call detected: %s (%s)", sample.Category, ev.From),
			Detail: fmt.Sprintf("Score %.2f. %s", sample.Score, sample.Summary),
			Data: map[string]any{
				"kind": "voice_scam", "customer_id": ev.Customer, "calling_number": ev.From, "category": sample.Category,
				"score": sample.Score, "summary": sample.Summary, "monologue": f.Monologue, "event_id": ev.ID, "sample_id": sample.ID,
				"direction": ev.Direction, "suggested_action": "unassign_did_and_review",
			},
		})
	}
}

func (s *Server) handleVoiceSamples(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := s.Store.VoiceSamples(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": list, "provider": providerName(s.VoiceProvider), "budget": s.voiceBudget()})
}

func (s *Server) voiceBudget() map[string]any {
	if s.Sampler == nil {
		return map[string]any{"enabled": false}
	}
	return map[string]any{"enabled": s.Sampler.Enabled, "per_hour": s.Sampler.Budget.PerHour, "per_customer_per_hour": s.Sampler.Budget.PerCustomerPerHour, "clip_seconds": s.Sampler.Budget.ClipSeconds}
}

// Customers: the operator's accounts and the numbers each may present.
func (s *Server) handleCustomers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := s.Store.Customers(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": list})
	case http.MethodPut, http.MethodPost:
		var c store.Customer
		if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&c); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		c.ID = strings.TrimSpace(c.ID)
		if c.ID == "" || len(c.ID) > 64 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id required, up to 64 characters"})
			return
		}
		clean := make([]string, 0, len(c.DIDs))
		for _, d := range c.DIDs {
			if d = strings.TrimSpace(d); d != "" {
				clean = append(clean, d)
			}
		}
		c.DIDs = clean
		if err := s.Store.PutCustomer(r.Context(), c); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.forgetCustomers()
		s.audit(r, "customer.put", c.ID, fmt.Sprintf("%s, %d numbers", c.Name, len(c.DIDs)))
		writeJSON(w, http.StatusOK, c)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or PUT"})
	}
}

func (s *Server) handleCustomer(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/customers/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id required"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		c, ok, err := s.Store.Customer(r.Context(), id)
		if err != nil || !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		act, _ := s.Store.CustomerActivity(r.Context(), id, time.Now().Add(-24*time.Hour))
		writeJSON(w, http.StatusOK, map[string]any{"customer": c, "last_24h": act, "asr": act.ASR(), "acd": act.ACD()})
	case http.MethodDelete:
		if err := s.Store.DeleteCustomer(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.forgetCustomers()
		s.audit(r, "customer.delete", id, "")
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or DELETE"})
	}
}

func clipStr(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}
