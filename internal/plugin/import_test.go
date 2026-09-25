package plugin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestImportPanel(t *testing.T) {
	if _, err := (*Runtime)(nil).Import(context.Background(), "numbers", []byte("x")); err == nil {
		t.Fatal("nil")
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/falcon/v1/plugins":
			_, _ = w.Write([]byte(`{"plugins":[{"slug":"numbers","kind":"view","surface":"native"},{"slug":"page","kind":"view","surface":"iframe"}]}`))
		case "/api/falcon/v1/plugins/numbers/import":
			if r.URL.Query().Get("mode") == "bad" {
				_, _ = w.Write([]byte("{"))
				return
			}
			if r.URL.Query().Get("mode") == "msg" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"no numbers found"}`))
				return
			}
			if r.URL.Query().Get("mode") == "err" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"choose a file"}`))
				return
			}
			if r.URL.Query().Get("mode") == "status" {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			if r.URL.Query().Get("mode") == "missing" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"title":"Number check","surface":"native","widget":"table","import":true,"columns":[{"key":"number","label":"Number"}],"rows":[{"number":"+16502530000"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer up.Close()
	rt := New(up.URL, "key", time.Minute, time.Millisecond)
	rt.HTTP = up.Client()
	rt.Load(context.Background())
	panel, err := rt.Import(context.Background(), "numbers", []byte("+16502530000\n"))
	if err != nil || !panel.Import || len(panel.Rows) != 1 {
		t.Fatalf("%+v %v", panel, err)
	}
	if _, err := rt.Import(context.Background(), "page", []byte("x")); err != ErrNotFound {
		t.Fatal(err)
	}
	if _, err := rt.Import(context.Background(), "missing", []byte("x")); err != ErrNotFound {
		t.Fatal(err)
	}
	rt.BaseURL = up.URL + "?mode=missing"
	// Path is BaseURL plus the route, so the query is not how the handler switches.
	rt.BaseURL = up.URL
	hit := func(mode string) error {
		rt.BaseURL = up.URL
		old := rt.HTTP
		rt.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			req, _ := http.NewRequest(r.Method, up.URL+r.URL.Path+"?mode="+mode, r.Body)
			req.Header = r.Header
			return old.Do(req)
		})}
		_, err := rt.Import(context.Background(), "numbers", []byte("x"))
		rt.HTTP = old
		return err
	}
	if err := hit("missing"); err != ErrNotFound {
		t.Fatalf("missing %v", err)
	}
	if err := hit("msg"); err == nil || !strings.Contains(err.Error(), "no numbers found") {
		t.Fatal(err)
	}
	if err := hit("err"); err == nil || !strings.Contains(err.Error(), "choose a file") {
		t.Fatal(err)
	}
	if err := hit("status"); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatal(err)
	}
	if err := hit("bad"); err == nil {
		t.Fatal("json")
	}
	rt.HTTP = nil
	rt.BaseURL = "http://127.0.0.1:1"
	if _, err := rt.Import(context.Background(), "numbers", []byte("x")); err == nil {
		t.Fatal("dial")
	}
	rt.BaseURL = "http://["
	rt.HTTP = up.Client()
	if _, err := rt.Import(context.Background(), "numbers", []byte("x")); err == nil {
		t.Fatal("url")
	}
	var okForm bytes.Buffer
	if _, err := writeImportForm(&okForm, []byte("x")); err != nil || okForm.Len() == 0 {
		t.Fatal(err)
	}
	saw := map[string]bool{}
	for n := 1; n <= 8; n++ {
		_, err := writeImportForm(&failAt{n: n}, []byte("x"))
		if err != nil {
			saw["err"] = true
		}
	}
	if !saw["err"] {
		t.Fatal("form writer")
	}
	buildImportForm = func(io.Writer, []byte) (string, error) {
		return "", errors.New("form")
	}
	t.Cleanup(func() { buildImportForm = writeImportForm })
	rt.BaseURL = up.URL
	rt.HTTP = up.Client()
	if _, err := rt.Import(context.Background(), "numbers", []byte("x")); err == nil {
		t.Fatal("form")
	}
}

type failAt struct{ n, at int }

func (f *failAt) Write(p []byte) (int, error) {
	f.at++
	if f.at >= f.n {
		return 0, errors.New("full")
	}
	return len(p), nil
}

type roundTrip func(*http.Request) (*http.Response, error)

func (r roundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return r(req) }
