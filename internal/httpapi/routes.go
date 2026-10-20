package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/callerapi/falcon/internal/store"
)

// handleRoutes lists and saves vendor routes: a tech prefix the switch
// adds so Falcon can name the vendor a call goes to.
func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		routes, err := s.Store.Routes(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": routes, "bridge": s.Media != nil})
	case http.MethodPost, http.MethodPut:
		var rt store.Route
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&rt); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		if t := strings.TrimSpace(rt.Target); t != "" {
			host, port, err := net.SplitHostPort(t)
			if err != nil || host == "" || port == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target must be host:port, or empty to send the call back to the switch"})
				return
			}
		}
		saved, err := s.Store.PutRoute(r.Context(), rt)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if s.Media != nil {
			_ = s.Media.ReloadRoutes(r.Context())
		}
		s.audit(r, "route.put", saved.Prefix, fmt.Sprintf("%s %s %s", saved.Label, saved.Carry, saved.Target))
		writeJSON(w, http.StatusOK, saved)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST"})
	}
}

func (s *Server) handleRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "DELETE required"})
		return
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/v1/routes/"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := s.Store.DeleteRoute(r.Context(), id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if s.Media != nil {
		_ = s.Media.ReloadRoutes(r.Context())
	}
	s.audit(r, "route.delete", fmt.Sprintf("#%d", id), "")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}
