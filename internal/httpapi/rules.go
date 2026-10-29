package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/lists"
)

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules, err := s.Store.Rules(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		extra, err := lists.PeerRules(s.Cfg.InternationalPeers, s.Cfg.CLIExemptPeers, s.Cfg.CLIExemptSPCs)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		rules = lists.Merge(rules, extra)
		if rules == nil {
			rules = []lists.Rule{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": rules})
	case http.MethodPost:
		var body struct {
			Kind    string `json:"kind"`
			Subject string `json:"subject"`
			Value   string `json:"value"`
			Note    string `json:"note"`
			TTL     string `json:"ttl"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		rule := lists.Rule{Kind: lists.Kind(strings.ToLower(body.Kind)), Subject: lists.Subject(strings.ToLower(body.Subject)), Value: body.Value, Note: strings.TrimSpace(body.Note)}
		if body.TTL != "" {
			d, err := time.ParseDuration(body.TTL)
			if err != nil || d <= 0 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ttl must be a duration such as 24h"})
				return
			}
			rule.ExpiresAt = time.Now().UTC().Add(d)
		}
		saved, err := s.Store.AddRule(r.Context(), rule)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := s.ReloadRules(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.audit(r, "rule.add", fmt.Sprintf("%s %s %s", saved.Kind, saved.Subject, saved.Value), fmt.Sprintf("#%d %s", saved.ID, saved.Note))
		writeJSON(w, http.StatusCreated, saved)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST"})
	}
}

func (s *Server) handleRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "DELETE required"})
		return
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/v1/rules/"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := s.Store.DeleteRule(r.Context(), id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := s.ReloadRules(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "rule.delete", fmt.Sprintf("#%d", id), "")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}
