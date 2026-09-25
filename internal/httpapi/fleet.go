package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/update"
)

const fleetBody = 8 << 20

func (s *Server) SetRelease(st update.Status) {
	s.releaseMu.Lock()
	s.release = st
	s.releaseMu.Unlock()
}

func (s *Server) currentRelease() update.Status {
	s.releaseMu.RLock()
	defer s.releaseMu.RUnlock()
	if s.release.Current == "" {
		return update.Status{Current: Version}
	}
	return s.release
}

func (s *Server) handleFleetEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var body struct {
		InstallID string        `json:"install_id"`
		Events    []store.Event `json:"events"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, fleetBody)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	body.InstallID = strings.TrimSpace(body.InstallID)
	if body.InstallID == "" || len(body.InstallID) > 64 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "install_id required"})
		return
	}
	if len(body.Events) > 50 {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "max 50 events"})
		return
	}
	accepted := 0
	for _, ev := range body.Events {
		ev.Peer = body.InstallID
		if ev.Switch == "" {
			ev.Switch = body.InstallID
		} else if !strings.HasPrefix(ev.Switch, body.InstallID+"/") {
			ev.Switch = body.InstallID + "/" + ev.Switch
		}
		if _, err := s.Store.InsertPeer(r.Context(), ev); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		accepted++
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": accepted})
}

func (s *Server) handleFleetRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}
	rules, err := s.Store.Rules(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	local := make([]lists.Rule, 0, len(rules))
	for _, rule := range rules {
		if rule.Origin == "" || rule.Origin == "local" {
			local = append(local, rule)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": local})
}

func (s *Server) handleFleetBehaviour(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}
	exclude := strings.TrimSpace(r.URL.Query().Get("exclude"))
	rows, err := s.Store.FleetActivity(r.Context(), time.Now().Add(-time.Hour), exclude, 5000)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if rows == nil {
		rows = map[string]store.Activity{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"callers": rows})
}
