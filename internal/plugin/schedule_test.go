package plugin

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestScheduleProxy(t *testing.T) {
	if _, err := (*Runtime)(nil).Schedule(context.Background(), "numbers"); err == nil {
		t.Fatal("nil")
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("mode") == "missing" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("mode") == "msg" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"choose at least one day"}`))
			return
		}
		if r.URL.Query().Get("mode") == "err" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unknown timezone"}`))
			return
		}
		if r.URL.Query().Get("mode") == "status" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if r.Method == http.MethodPut && r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "type", http.StatusUnsupportedMediaType)
			return
		}
		_, _ = w.Write([]byte(`{"state":"scheduled","enabled":true}`))
	}))
	defer up.Close()
	rt := New(up.URL, "key", time.Minute, time.Millisecond)
	rt.HTTP = up.Client()
	rt.Load(context.Background())
	// The test catalog is empty until the handler returns plugins. Point List by loading a catalog server.
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"plugins":[{"slug":"numbers","kind":"view","surface":"native"},{"slug":"page","kind":"view","surface":"iframe"}]}`))
	}))
	defer catalog.Close()
	rt = New(catalog.URL, "key", time.Minute, time.Millisecond)
	rt.HTTP = catalog.Client()
	rt.Load(context.Background())
	rt.BaseURL = up.URL
	rt.HTTP = up.Client()
	raw, err := rt.Schedule(context.Background(), "numbers")
	if err != nil || !strings.Contains(string(raw), "scheduled") {
		t.Fatalf("get %s %v", raw, err)
	}
	raw, err = rt.SaveSchedule(context.Background(), "numbers", []byte(`{"enabled":true}`))
	if err != nil || !strings.Contains(string(raw), "scheduled") {
		t.Fatalf("put %s %v", raw, err)
	}
	if _, err := rt.Schedule(context.Background(), "page"); err != ErrNotFound {
		t.Fatal(err)
	}
	hit := func(mode string) error {
		old := rt.HTTP
		rt.HTTP = &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
			next, _ := http.NewRequest(req.Method, up.URL+req.URL.Path+"?mode="+mode, req.Body)
			next.Header = req.Header
			return old.Do(next)
		})}
		_, err := rt.Schedule(context.Background(), "numbers")
		rt.HTTP = old
		return err
	}
	if err := hit("missing"); err != ErrNotFound {
		t.Fatal(err)
	}
	if err := hit("msg"); err == nil || !strings.Contains(err.Error(), "one day") {
		t.Fatal(err)
	}
	if err := hit("err"); err == nil || !strings.Contains(err.Error(), "timezone") {
		t.Fatal(err)
	}
	if err := hit("status"); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatal(err)
	}
	rt.HTTP = nil
	rt.BaseURL = "http://127.0.0.1:1"
	if _, err := rt.Schedule(context.Background(), "numbers"); err == nil {
		t.Fatal("dial")
	}
	rt.BaseURL = "http://["
	rt.HTTP = up.Client()
	if _, err := rt.Schedule(context.Background(), "numbers"); err == nil {
		t.Fatal("url")
	}
	rt.BaseURL = up.URL
	rt.HTTP = &http.Client{Transport: errBodyTransport{}}
	if _, err := rt.Schedule(context.Background(), "numbers"); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}

type errBodyTransport struct{}

func (errBodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(errReader{}),
		Header:     make(http.Header),
	}, nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
