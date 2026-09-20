package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A cross-origin HTML form carries Basic credentials automatically. It can
// only send form content types. Mutations refuse those, so the form cannot
// add an allow rule even with the operator logged in.
func TestMutationsRefuseFormContentTypesWithBasicAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.Cfg.DashboardUser = "admin"
	srv.Cfg.DashboardPassword = "pw"
	h := srv.Handler()

	body := `{"kind":"allow","subject":"ip","value":"0.0.0.0/0"}`
	for _, ct := range []string{"application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "text/plain", ""} {
		req := httptest.NewRequest(http.MethodPost, "/v1/rules", bytes.NewBufferString(body))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		req.SetBasicAuth("admin", "pw")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("content type %q with basic auth: got %d, want 415", ct, w.Code)
		}
	}
	// The same body as JSON with Basic auth is the dashboard's own path.
	req := httptest.NewRequest(http.MethodPost, "/v1/rules", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", "pw")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("json with basic auth: %d %s", w.Code, w.Body.String())
	}
}

// The query token is for EventSource and downloads. It never authorises a
// mutation, so a token that leaks into a log or a referrer cannot change
// rules.
func TestQueryTokenIsReadOnly(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodPost, "/v1/rules?token=secret", bytes.NewBufferString(`{"kind":"deny","subject":"number","value":"+15551230000"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("query token on a mutation: got %d, want 401", w.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/rules?token=secret", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("query token on a read: got %d, want 200", w.Code)
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.Handler()
	for _, path := range []string{"/v1/health", "/v1/stats", "/"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Falcon-Token", "secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		for k, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "no-referrer",
		} {
			if got := w.Header().Get(k); got != want {
				t.Fatalf("%s %s=%q want %q", path, k, got, want)
			}
		}
		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
			t.Fatalf("%s csp %q", path, csp)
		}
	}
}

// Raw SIP is the one place a subscriber number sits in the clear. It can be
// switched off entirely and it is never streamed.
func TestRawSIPNotStoredWhenDisabled(t *testing.T) {
	srv, db := newTestServer(t)
	srv.Cfg.StoreRawSIP = false
	screen(t, srv, "198.51.100.20", cleanInvite("+14155550100", "Acme-SBC/1.0"))
	events := waitEvents(t, db, 1)
	full, err := db.Get(context.Background(), events[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if full.RawSIP != "" {
		t.Fatalf("raw sip stored despite FALCON_STORE_RAW_SIP=false: %q", full.RawSIP)
	}
}
