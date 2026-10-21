package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/callerapi/falcon/internal/compliance"
	"github.com/callerapi/falcon/internal/store"
)

// upstreamView is one upstream with its last FCC check.
type upstreamView struct {
	store.Upstream
	Check *compliance.Result `json:"check,omitempty"`
	Words string             `json:"words,omitempty"`
}

func (s *Server) upstreamViews(ctx context.Context) ([]upstreamView, error) {
	ups, err := s.Store.Upstreams(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]upstreamView, 0, len(ups))
	for _, u := range ups {
		out = append(out, s.upstreamView(u))
	}
	return out, nil
}

func (s *Server) upstreamView(u store.Upstream) upstreamView {
	v := upstreamView{Upstream: u}
	if s.Compliance != nil {
		if r, ok := s.Compliance.Result(u.ID); ok {
			v.Check, v.Words = &r, compliance.Words(r)
		}
	}
	return v
}

// evaluateCompliance runs the autopilot after the registry changes. The
// change is saved either way. A failure is logged and shown on the next run.
func (s *Server) evaluateCompliance(ctx context.Context) {
	if s.Compliance == nil {
		return
	}
	if err := s.Compliance.Evaluate(ctx); err != nil {
		log.Printf("falcon fcc: evaluate: %v", err)
	}
}

func (s *Server) complianceStatus(ctx context.Context) map[string]any {
	out := map[string]any{"enabled": s.Compliance != nil, "mode": s.FCCMode(ctx)}
	if s.Compliance != nil {
		out["list"] = s.Compliance.Status()
	}
	return out
}

func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		views, err := s.upstreamViews(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": views, "fcc": s.complianceStatus(r.Context())})
	case http.MethodPost, http.MethodPut:
		var body store.Upstream
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		u, err := compliance.NormalizeUpstream(body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		saved, err := s.Store.PutUpstream(r.Context(), u)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		s.audit(r, "upstream.save", saved.Name, fmt.Sprintf("#%d rmd=%s frn=%s, %d addresses, %d signer codes", saved.ID, saved.RMD, saved.FRN, len(saved.IPs), len(saved.SPCs)))
		s.evaluateCompliance(r.Context())
		if fresh, ok, err := s.Store.Upstream(r.Context(), saved.ID); err == nil && ok {
			saved = fresh
		}
		status := http.StatusOK
		if body.ID == 0 {
			status = http.StatusCreated
		}
		writeJSON(w, status, s.upstreamView(saved))
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST"})
	}
}

func (s *Server) handleUpstream(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/v1/upstreams/"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	u, ok, err := s.Store.Upstream(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no upstream with that id"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.upstreamView(u))
	case http.MethodDelete:
		if err := s.Store.DeleteUpstream(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.audit(r, "upstream.delete", u.Name, fmt.Sprintf("#%d", id))
		s.evaluateCompliance(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or DELETE"})
	}
}

// handleCompliance is the autopilot state and its log.
func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.Store.ComplianceLog(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := s.complianceStatus(r.Context())
	out["log"] = entries
	writeJSON(w, http.StatusOK, out)
}
