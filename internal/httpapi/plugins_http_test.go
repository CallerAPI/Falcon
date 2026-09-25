package httpapi

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/plugin"
)

func TestPluginHTTPRoutes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/falcon/v1/plugins":
			_, _ = w.Write([]byte(`{"plugins":[{"slug":"numbers","title":"Number check","kind":"view","surface":"native"},{"slug":"page","title":"Page","kind":"view","surface":"iframe"}]}`))
		case strings.HasSuffix(r.URL.Path, "/view"):
			_, _ = w.Write([]byte(`{"title":"Number check","surface":"native","widget":"table","columns":[{"key":"status","label":"Status"}],"rows":[{"status":"clear"}]}`))
		case strings.HasSuffix(r.URL.Path, "/frame"):
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!DOCTYPE html><p>Page</p>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	rt := plugin.New(upstream.URL, "key", time.Minute, time.Millisecond)
	rt.HTTP = upstream.Client()
	rt.Load(context.Background())
	srv, _ := newTestServer(t)
	srv.Plugins = rt

	list := do(t, srv, http.MethodGet, "/v1/plugins", nil)
	if list.Code != 200 || !strings.Contains(list.Body.String(), "numbers") {
		t.Fatalf("list %d %s", list.Code, list.Body.String())
	}
	if post := do(t, srv, http.MethodPost, "/v1/plugins", nil); post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("post %d", post.Code)
	}
	view := do(t, srv, http.MethodGet, "/v1/plugins/numbers/view?q=%2B14155550100", nil)
	if view.Code != 200 || !strings.Contains(view.Body.String(), "clear") {
		t.Fatalf("view %d %s", view.Code, view.Body.String())
	}
	frame := do(t, srv, http.MethodGet, "/v1/plugins/page/frame", nil)
	if frame.Code != 200 || !strings.Contains(frame.Body.String(), "Page") || strings.Contains(frame.Header().Get("Content-Type"), "json") {
		t.Fatalf("frame %d %s", frame.Code, frame.Body.String())
	}
	if missing := do(t, srv, http.MethodGet, "/v1/plugins/missing/view", nil); missing.Code != 404 {
		t.Fatalf("missing view %d", missing.Code)
	}
	empty := plugin.New(upstream.URL, "key", time.Minute, time.Millisecond)
	srv.Plugins = empty
	if blank := do(t, srv, http.MethodGet, "/v1/plugins", nil); blank.Code != 200 || !strings.Contains(blank.Body.String(), `"plugins":[]`) {
		t.Fatalf("empty list %d %s", blank.Code, blank.Body.String())
	}
	srv.Plugins = rt
	if missing := do(t, srv, http.MethodGet, "/v1/plugins/nope", nil); missing.Code != 404 {
		t.Fatalf("missing %d", missing.Code)
	}
	bare, _ := newTestServer(t)
	if off := do(t, bare, http.MethodGet, "/v1/plugins/numbers/view", nil); off.Code != 404 {
		t.Fatalf("plugins off %d", off.Code)
	}
	if bad := do(t, srv, http.MethodPost, "/v1/plugins/numbers/view", nil); bad.Code != http.StatusMethodNotAllowed {
		t.Fatalf("view post %d", bad.Code)
	}
	if bad := do(t, srv, http.MethodGet, "/v1/plugins/a.b/view", nil); bad.Code != 404 {
		t.Fatalf("dot %d", bad.Code)
	}
	if nativeFrame := do(t, srv, http.MethodGet, "/v1/plugins/numbers/frame", nil); nativeFrame.Code != 404 {
		t.Fatalf("native frame %d", nativeFrame.Code)
	}
	upstream.Close()
	if downView := do(t, srv, http.MethodGet, "/v1/plugins/numbers/view", nil); downView.Code != http.StatusBadGateway {
		t.Fatalf("view down %d", downView.Code)
	}
	if down := do(t, srv, http.MethodGet, "/v1/plugins/page/frame", nil); down.Code != http.StatusBadGateway {
		t.Fatalf("frame down %d", down.Code)
	}
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/falcon/v1/plugins":
			_, _ = w.Write([]byte(`{"plugins":[{"slug":"numbers","title":"Number check","kind":"view","surface":"native"}]}`))
		case strings.HasSuffix(r.URL.Path, "/import"):
			if r.Header.Get("X-Auth") == "" || !strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"title":"Number check","surface":"native","widget":"table","import":true,"columns":[{"key":"number","label":"Number"}],"rows":[{"number":"+16502530000","status":"clear"}],"stats":[{"label":"Numbers","value":"1"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)
	rt = plugin.New(upstream.URL, "key", time.Minute, time.Millisecond)
	rt.HTTP = upstream.Client()
	rt.Load(context.Background())
	srv.Plugins = rt
	req := httptest.NewRequest(http.MethodPost, "/v1/plugins/numbers/import", strings.NewReader("number,+16502530000\n"))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Falcon-Token", "secret")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "+16502530000") || !strings.Contains(rec.Body.String(), `"import":true`) {
		t.Fatalf("import %d %s", rec.Code, rec.Body.String())
	}
	bearer := httptest.NewRequest(http.MethodPost, "/v1/plugins/numbers/import", strings.NewReader("+16502530000\n"))
	bearer.Header.Set("Content-Type", "text/plain")
	bearer.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, bearer)
	if rec.Code != 200 {
		t.Fatalf("bearer %d %s", rec.Code, rec.Body.String())
	}
	srv.Cfg.DashboardUser = "admin"
	srv.Cfg.DashboardPassword = "pw"
	basic := httptest.NewRequest(http.MethodPost, "/v1/plugins/numbers/import", strings.NewReader("+16502530000\n"))
	basic.Header.Set("Content-Type", "text/plain")
	basic.SetBasicAuth("admin", "pw")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, basic)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("basic form %d", rec.Code)
	}
	if bad := do(t, srv, http.MethodGet, "/v1/plugins/numbers/import", nil); bad.Code != http.StatusMethodNotAllowed {
		t.Fatalf("import get %d", bad.Code)
	}
	if missing := do(t, srv, http.MethodPost, "/v1/plugins/missing/import", "x"); missing.Code != http.StatusNotFound {
		t.Fatalf("import missing %d", missing.Code)
	}
	bare.Plugins = nil
	if off := do(t, bare, http.MethodPost, "/v1/plugins/numbers/import", "x"); off.Code != http.StatusNotFound {
		t.Fatalf("import off %d", off.Code)
	}
	var form bytes.Buffer
	mw := multipart.NewWriter(&form)
	part, err := mw.CreateFormFile("file", "list.csv")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("+16502530000\n"))
	_ = mw.Close()
	req = httptest.NewRequest(http.MethodPost, "/v1/plugins/numbers/import", &form)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Falcon-Token", "secret")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("multipart %d %s", rec.Code, rec.Body.String())
	}
	var note bytes.Buffer
	nw := multipart.NewWriter(&note)
	_ = nw.WriteField("note", "x")
	_ = nw.Close()
	noFile := httptest.NewRequest(http.MethodPost, "/v1/plugins/numbers/import", &note)
	noFile.Header.Set("Content-Type", nw.FormDataContentType())
	noFile.Header.Set("X-Falcon-Token", "secret")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, noFile)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no file %d", rec.Code)
	}
	badForm := httptest.NewRequest(http.MethodPost, "/v1/plugins/numbers/import", strings.NewReader("nope"))
	badForm.Header.Set("Content-Type", "multipart/form-data; boundary=missing")
	badForm.Header.Set("X-Falcon-Token", "secret")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, badForm)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad form %d", rec.Code)
	}
	upstream.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	})
	if failed := do(t, srv, http.MethodPost, "/v1/plugins/numbers/import", "x"); failed.Code != http.StatusBadGateway {
		t.Fatalf("import down %d %s", failed.Code, failed.Body.String())
	}
}

func TestPluginScheduleRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/falcon/v1/plugins":
			_, _ = w.Write([]byte(`{"plugins":[{"slug":"numbers","kind":"view","surface":"native"}]}`))
		case strings.HasSuffix(r.URL.Path, "/schedule") && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"state":"off","enabled":false}`))
		case strings.HasSuffix(r.URL.Path, "/schedule") && r.Method == http.MethodPut:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"choose at least one day"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	rt := plugin.New(upstream.URL, "key", time.Minute, time.Millisecond)
	rt.HTTP = upstream.Client()
	rt.Load(context.Background())
	srv, _ := newTestServer(t)
	srv.Plugins = rt
	got := do(t, srv, http.MethodGet, "/v1/plugins/numbers/schedule", nil)
	if got.Code != 200 || !strings.Contains(got.Body.String(), `"state":"off"`) {
		t.Fatalf("get %d %s", got.Code, got.Body.String())
	}
	bad := do(t, srv, http.MethodPut, "/v1/plugins/numbers/schedule", map[string]any{"enabled": true})
	if bad.Code != http.StatusBadGateway || !strings.Contains(bad.Body.String(), "one day") {
		t.Fatalf("put %d %s", bad.Code, bad.Body.String())
	}
	if post := do(t, srv, http.MethodPost, "/v1/plugins/numbers/schedule", "x"); post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("post %d", post.Code)
	}
	if missing := do(t, srv, http.MethodGet, "/v1/plugins/missing/schedule", nil); missing.Code != http.StatusNotFound {
		t.Fatalf("missing %d", missing.Code)
	}
	bare, _ := newTestServer(t)
	if off := do(t, bare, http.MethodGet, "/v1/plugins/numbers/schedule", nil); off.Code != http.StatusNotFound {
		t.Fatalf("off %d", off.Code)
	}
	req := httptest.NewRequest(http.MethodPut, "/v1/plugins/numbers/schedule", boomReader{})
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Falcon-Token", "secret")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("read %d", rec.Code)
	}
}

type boomReader struct{}

func (boomReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
