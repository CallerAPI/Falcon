package feed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLiveVerify_ReadsIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/bcid/v1/verify" || r.Header.Get("X-Auth") != "key" {
			t.Fatalf("path=%s auth=%s", r.URL.Path, r.Header.Get("X-Auth"))
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["from"] != "+18883578668" || body["to"] != "+14155550123" {
			t.Fatalf("body = %#v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{
				"verdict": "verified",
				"action":  "allow",
				"identity": map[string]any{
					"verified": true,
					"name":     "✓ Springfield Bank",
					"logo_url": "/api/bcid/v1/logos/bab28c367e87d8cf",
				},
			},
		})
	}))
	defer srv.Close()

	live := &Live{BaseURL: srv.URL, APIKey: "key", HTTP: srv.Client()}
	got, err := live.Verify(context.Background(), "+18883578668", "+14155550123", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != "verified" || got.Identity == nil || got.Identity.Name != "✓ Springfield Bank" {
		t.Fatalf("got %+v", got)
	}
}

func TestLiveVerify_HTTPErrorIsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	live := &Live{BaseURL: srv.URL, APIKey: "key", HTTP: srv.Client()}
	got, err := live.Verify(context.Background(), "+18883578668", "+14155550123", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != "" {
		t.Fatalf("fail-open returned %q", got.Verdict)
	}
}
