package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/callerapi/falcon/internal/plugin"
	"github.com/callerapi/falcon/sdk"
	"github.com/coder/websocket"
)

type bridgeRun struct {
	cancel context.CancelFunc
	key    string
	url    string
	err    string
	up     bool
	last   time.Time
}

type bridgeHost struct {
	mu   sync.Mutex
	live bool
	runs map[string]*bridgeRun
}

func (s *Server) startBridges() {
	if s.bridges == nil {
		s.bridges = &bridgeHost{runs: map[string]*bridgeRun{}}
	}
	s.bridges.mu.Lock()
	s.bridges.live = true
	s.bridges.mu.Unlock()
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		s.bridges.sync(s)
		for range t.C {
			s.bridges.sync(s)
		}
	}()
}

// SetPlugins publishes the catalog. The bridge sync loop reads the pointer
// under bridgeHost.mu, so a write after Init takes that lock too.
func (s *Server) SetPlugins(rt *plugin.Runtime) {
	s.publishPlugins(rt, nil)
}

// publishPlugins writes the catalog. A non-nil live value is stored in the
// same critical section, so sync cannot dial a catalog the caller just paused.
func (s *Server) publishPlugins(rt *plugin.Runtime, live *bool) {
	if s.bridges != nil {
		s.bridges.mu.Lock()
		defer s.bridges.mu.Unlock()
		if live != nil {
			s.bridges.live = *live
		}
	}
	s.Plugins = rt
}

func (h *bridgeHost) sync(s *Server) {
	h.mu.Lock()
	plugins := s.Plugins
	h.mu.Unlock()
	if plugins == nil {
		return
	}
	want := map[string]sdk.Manifest{}
	for _, item := range plugins.List() {
		if item.Kind != "bridge" || item.Bridge == nil {
			continue
		}
		if err := sdk.ValidateBridge(*item.Bridge); err != nil {
			continue
		}
		want[item.Slug] = item
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.runs == nil {
		h.runs = map[string]*bridgeRun{}
	}
	for slug, run := range h.runs {
		if _, ok := want[slug]; !ok && run.cancel != nil {
			run.cancel()
			delete(h.runs, slug)
		}
	}
	if !h.live {
		return
	}
	for slug, item := range want {
		values := h.load(s, slug)
		rawURL, headers, err := item.Bridge.Materialize(values)
		if err != nil {
			continue
		}
		key := rawURL + "\n" + headers["Authorization"]
		if run := h.runs[slug]; run != nil && run.key == key {
			continue
		}
		if run := h.runs[slug]; run != nil && run.cancel != nil {
			run.cancel()
		}
		ctx, cancel := context.WithCancel(context.Background())
		h.runs[slug] = &bridgeRun{cancel: cancel, key: key, url: rawURL}
		go s.bridgeLoop(ctx, h, slug, rawURL, headers)
	}
}

func (h *bridgeHost) load(s *Server, slug string) map[string]string {
	raw, err := s.Store.KVGet(context.Background(), bridgeKey(slug))
	if err != nil || raw == "" {
		return map[string]string{}
	}
	var values map[string]string
	if json.Unmarshal([]byte(raw), &values) != nil {
		return map[string]string{}
	}
	return values
}

func bridgeKey(slug string) string { return "bridge:" + slug }

func (s *Server) bridgeLoop(ctx context.Context, h *bridgeHost, slug, rawURL string, headers map[string]string) {
	for {
		if ctx.Err() != nil {
			return
		}
		err := s.bridgeSession(ctx, h, slug, rawURL, headers)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			h.mark(slug, false, err.Error(), time.Time{})
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (s *Server) bridgeSession(ctx context.Context, h *bridgeHost, slug, rawURL string, headers map[string]string) error {
	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	hdr := http.Header{}
	for name, value := range headers {
		hdr.Set(name, value)
	}
	conn, _, err := websocket.Dial(dialCtx, rawURL, &websocket.DialOptions{
		HTTPHeader: hdr,
		HTTPClient: &http.Client{Transport: bridgeTransport()},
	})
	if err != nil {
		return err
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(1 << 20)
	h.mark(slug, true, "", time.Time{})
	for {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		if len(msg) > 1<<20 {
			continue
		}
		s.acceptTranscript(msg)
		h.mark(slug, true, "", time.Now().UTC())
	}
}

func bridgeTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if privateIP(ip.IP) {
					return nil, errPrivate
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
}

var errPrivate = errString("refusing private address")

type errString string

func (e errString) Error() string { return string(e) }

func privateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func (h *bridgeHost) mark(slug string, up bool, errText string, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	run := h.runs[slug]
	if run == nil {
		return
	}
	run.up = up
	if errText != "" {
		run.err = errText
		run.up = false
	}
	if !at.IsZero() {
		run.last = at
		run.err = ""
		run.up = true
	}
}

func (s *Server) bridgeManifest(slug string) (sdk.Manifest, bool) {
	if s.Plugins == nil {
		return sdk.Manifest{}, false
	}
	for _, item := range s.Plugins.List() {
		if item.Slug == slug && item.Kind == "bridge" && item.Bridge != nil {
			if err := sdk.ValidateBridge(*item.Bridge); err != nil {
				return sdk.Manifest{}, false
			}
			return item, true
		}
	}
	return sdk.Manifest{}, false
}

func (s *Server) handleBridgeSettings(w http.ResponseWriter, r *http.Request, slug string) {
	item, ok := s.bridgeManifest(slug)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.bridgeView(item))
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		var in struct {
			Values map[string]string `json:"values"`
		}
		if json.Unmarshal(body, &in) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		current := s.bridges.load(s, slug)
		next := map[string]string{}
		for _, setting := range item.Bridge.Settings {
			value := strings.TrimSpace(in.Values[setting.Key])
			if value == "" && setting.Secret {
				value = current[setting.Key]
			}
			next[setting.Key] = value
		}
		if _, _, err := item.Bridge.Materialize(next); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "check the values"})
			return
		}
		raw, _ := json.Marshal(next)
		if err := s.Store.KVSet(r.Context(), bridgeKey(slug), string(raw)); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.bridges.mu.Lock()
		if run := s.bridges.runs[slug]; run != nil && run.cancel != nil {
			run.cancel()
			delete(s.bridges.runs, slug)
		}
		s.bridges.mu.Unlock()
		s.bridges.sync(s)
		writeJSON(w, http.StatusOK, s.bridgeView(item))
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
	}
}

func (s *Server) bridgeView(item sdk.Manifest) map[string]any {
	values := s.bridges.load(s, item.Slug)
	fields := make([]map[string]any, 0, len(item.Bridge.Settings))
	for _, setting := range item.Bridge.Settings {
		row := map[string]any{
			"key": setting.Key, "label": setting.Label, "secret": setting.Secret,
		}
		if setting.Secret {
			row["set"] = values[setting.Key] != ""
		} else {
			row["value"] = values[setting.Key]
		}
		fields = append(fields, row)
	}
	s.bridges.mu.Lock()
	run := s.bridges.runs[item.Slug]
	up, errText, at := false, "", ""
	if run != nil {
		up = run.up
		errText = run.err
		if !run.last.IsZero() {
			at = run.last.Format(time.RFC3339)
		}
	}
	s.bridges.mu.Unlock()
	return map[string]any{
		"slug": item.Slug, "title": item.Title, "summary": item.Summary,
		"sink": item.Bridge.Sink, "connected": up, "last_error": errText, "last_at": at,
		"settings": fields,
	}
}
