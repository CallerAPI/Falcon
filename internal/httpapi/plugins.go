package httpapi

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/callerapi/falcon/internal/plugin"
	"github.com/callerapi/falcon/sdk"
)

func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
		return
	}
	items := []sdk.Manifest{}
	if s.Plugins != nil {
		if listed := s.Plugins.List(); listed != nil {
			items = listed
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"plugins": items})
}

func (s *Server) handlePluginView(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/plugins/")
	slug, kind, ok := strings.Cut(rest, "/")
	if !ok || slug == "" || strings.Contains(slug, ".") || (kind != "view" && kind != "frame" && kind != "import" && kind != "schedule") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if kind == "schedule" {
		if s.Plugins == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		s.schedulePlugin(w, r, slug)
		return
	}
	if kind == "import" {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
			return
		}
		if s.Plugins == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		s.importPlugin(w, r, slug)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
		return
	}
	if s.Plugins == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if kind == "frame" {
		s.writePluginPage(w, r, slug)
		return
	}
	panel, err := s.Plugins.Panel(r.Context(), slug, r.URL.Query().Get("q"))
	if errors.Is(err, plugin.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "plugin view unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, panel)
}

func (s *Server) schedulePlugin(w http.ResponseWriter, r *http.Request, slug string) {
	var (
		raw []byte
		err error
	)
	switch r.Method {
	case http.MethodGet:
		raw, err = s.Plugins.Schedule(r.Context(), slug)
	case http.MethodPut:
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 4096))
		if readErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid schedule"})
			return
		}
		raw, err = s.Plugins.SaveSchedule(r.Context(), slug, body)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
		return
	}
	if errors.Is(err, plugin.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) importPlugin(w http.ResponseWriter, r *http.Request, slug string) {
	body, err := readImport(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "choose a file"})
		return
	}
	panel, err := s.Plugins.Import(r.Context(), slug, body)
	if errors.Is(err, plugin.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, panel)
}

func readImport(r *http.Request) ([]byte, error) {
	if strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			return nil, err
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return io.ReadAll(io.LimitReader(file, 32<<20+1))
	}
	return io.ReadAll(io.LimitReader(r.Body, 32<<20+1))
}

func (s *Server) writePluginPage(w http.ResponseWriter, r *http.Request, slug string) {
	body, err := s.Plugins.Page(r.Context(), slug, r.URL.Query().Get("q"))
	if errors.Is(err, plugin.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "plugin page unavailable"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
