package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/callerapi/falcon/internal/alerts"
	"github.com/callerapi/falcon/internal/media"
	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/voice"
)

// handleRecording serves a call recording to the dashboard player. The
// id is a voice sample (/v1/recordings/12.wav) or a bridged call
// (/v1/recordings/call-12.wav). Range requests work, so the player seeks.
func (s *Server) handleRecording(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/recordings/"), ".wav")
	rel, ok := s.recordingByName(r.Context(), name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "recording not found or expired"})
		return
	}
	path, ok := store.RecordingPath(s.Cfg.RecordingsPath(), rel)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "recording not found"})
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "recording expired"})
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "recording expired"})
		return
	}
	w.Header().Set("Content-Type", "audio/wav")
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Header().Set("Content-Disposition", `inline; filename="falcon-`+name+`.wav"`)
	http.ServeContent(w, r, "", info.ModTime(), f)
}

func (s *Server) recordingByName(ctx context.Context, name string) (string, bool) {
	if id, ok := strings.CutPrefix(name, "call-"); ok {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil || n <= 0 {
			return "", false
		}
		m, found, err := s.Store.MediaCall(ctx, n)
		return m.Recording, err == nil && found && m.Recording != ""
	}
	n, err := strconv.ParseInt(name, 10, 64)
	if err != nil || n <= 0 {
		return "", false
	}
	v, found, err := s.Store.VoiceSample(ctx, n)
	return v.AudioPath, err == nil && found && v.AudioPath != ""
}

// aiBudget caps model work on bridged recordings per hour. A recording
// past the cap is kept and analysed on the host only.
type aiBudget struct {
	mu    sync.Mutex
	hour  int64
	count int
}

func (b *aiBudget) take(perHour int) bool {
	if perHour <= 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	h := time.Now().Unix() / 3600
	if h != b.hour {
		b.hour, b.count = h, 0
	}
	if b.count >= perHour {
		return false
	}
	b.count++
	return true
}

var bridgeAI aiBudget

// IngestRecording takes a finished bridged call: it reads the stereo WAV,
// runs the free checks on the host, stores the sample, and sends it to
// the voice provider within the hourly budget.
func (s *Server) IngestRecording(ctx context.Context, rec media.Recording) {
	path, ok := store.RecordingPath(s.Cfg.RecordingsPath(), rec.Path)
	if !ok {
		return
	}
	wav, err := os.ReadFile(path)
	if err != nil {
		log.Printf("falcon recording: %v", err)
		return
	}
	ev, _, _ := s.Store.EventByCallID(ctx, rec.CallID)
	from := firstNonEmpty(ev.From, rec.From)
	s.ingestAudio(ctx, wav, rec.Path, ev, rec.CallID, from, bridgeAI.take(s.Cfg.VoiceSamplesPerHour))
}

// ingestAudio is the voice pipeline both the bridge and uploaded clips use.
func (s *Server) ingestAudio(ctx context.Context, wav []byte, audioPath string, ev store.Event, callID, from string, useProvider bool) (store.VoiceSample, voice.Features, error) {
	clip, err := voice.DecodeWAV(wav)
	if err != nil {
		return store.VoiceSample{}, voice.Features{}, err
	}
	f := voice.Analyse(clip)
	recent, _ := s.Store.RecentPHashes(ctx, time.Now().Add(-24*time.Hour), 2000)
	sample := store.VoiceSample{
		EventID: ev.ID, CallID: callID, Seconds: f.Seconds, Channels: f.Channels, PHash: f.PHash,
		CallerSpeech: f.CallerSpeech, CalleeSpeech: f.CalleeSpeech, RepeatCount: voice.Repeats(f.PHash, recent),
		Customer: ev.Customer, From: from, AudioPath: audioPath,
	}
	id, err := s.Store.AddVoiceSample(ctx, sample)
	if err != nil {
		return store.VoiceSample{}, f, err
	}
	sample.ID = id
	if s.metrics != nil {
		s.metrics.clip(f.Monologue, sample.RepeatCount)
	}
	if sample.RepeatCount+1 >= 3 && s.Alerts != nil {
		s.Alerts.FireNow(ctx, alerts.Fired{
			Key: "repeat_recording:" + from, Severity: "critical",
			Title:  fmt.Sprintf("%s is playing the same recording on every call", from),
			Detail: fmt.Sprintf("The opening of this call matches %d earlier clips in 24 hours. That is a prerecorded message, not a person. No model was needed to tell.", sample.RepeatCount),
			Data:   map[string]any{"kind": "repeat_recording", "calling_number": from, "customer_id": ev.Customer, "repeat_count": sample.RepeatCount + 1, "event_id": ev.ID, "suggested_action": "block_number_and_review_customer"},
		})
	}
	if s.VoiceProvider != nil && useProvider {
		go s.classifyClip(sample, ev, wav, f)
	}
	if b, err := json.Marshal(map[string]any{"type": "voice", "event_id": ev.ID, "call_id": callID, "sample_id": id, "recorded": audioPath != ""}); err == nil {
		s.hub.publish(b)
	}
	return sample, f, nil
}
