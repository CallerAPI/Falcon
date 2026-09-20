package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/callerapi/falcon/internal/demo"
	"github.com/callerapi/falcon/internal/feed"
	"github.com/callerapi/falcon/internal/ipintel"
	"github.com/callerapi/falcon/internal/store"
)

// handleDemo swaps the running store between the free and paid Zoom seeds.
func (s *Server) handleDemo(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.Demo {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "demo mode is off"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var body struct {
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	profile, err := demo.Normalize(body.Profile)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	dir := demo.Dir(s.Cfg.DemoDir)
	if !fileExists(demo.DBPath(dir, profile)) {
		if err := demo.Seed(dir); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	sqlStore, ok := s.Store.(*store.SQLite)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "demo swap needs the sqlite store"})
		return
	}
	if err := sqlStore.ReplaceFile(demo.DBPath(dir, profile), s.Cfg.DBPath); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	intel := demo.IntelPath(dir, profile)
	if s.IPIntel == nil {
		s.IPIntel = ipintel.New(intel, "", "", time.Hour)
	} else {
		s.IPIntel.SetFile(intel)
	}
	s.IPIntel.Load(r.Context())
	s.Cfg.IPIntelFile = intel
	s.Cfg.DemoProfile = profile
	if profile == demo.ProfilePaid {
		if s.Feed == nil {
			s.Feed = feed.NewSpam("", "demo", time.Hour)
		}
		if nums, err := demo.SpamDIDs(dir); err == nil {
			s.Feed.LoadNumbers(nums)
		}
	} else if s.Feed != nil {
		s.Feed.LoadNumbers(nil)
	}
	if err := s.ReloadRules(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "demo_swap", profile, intel)
	writeJSON(w, http.StatusOK, map[string]any{"profile": profile, "ip_intel": intel})
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
