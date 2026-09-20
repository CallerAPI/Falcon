package export

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

func TestCallerAPITelemetryIsRedactedAndKeyless(t *testing.T) {
	var gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("X-Auth")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &CallerAPI{BaseURL: srv.URL, InstallID: "inst", Version: "0.9.0", HMACKey: []byte("secret")}
	ev := store.Event{
		ReceivedAt: time.Now(),
		Action:     score.ActionReject,
		From:       "+13125550188",
		To:         "+14155550123",
		CallID:     "abc",
		RawSIP:     "INVITE sip:+14155550123@x SIP/2.0\r\nTo: <sip:+14155550123@x>\r\nFrom: <sip:+13125550188@y>\r\n\r\nv=0\r\n",
	}
	if err := c.Ingest(context.Background(), []store.Event{ev}); err != nil {
		t.Fatal(err)
	}
	if gotPath != Endpoint {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "" {
		t.Fatalf("X-Auth sent without a key: %q", gotAuth)
	}
	if strings.Contains(gotBody, "4155550123") || strings.Contains(gotBody, "v=0") {
		t.Fatalf("called party or SDP leaked:\n%s", gotBody)
	}
	var req telemetryRequest
	if err := json.Unmarshal([]byte(gotBody), &req); err != nil {
		t.Fatal(err)
	}
	if req.InstallID != "inst" || req.Version != "0.9.0" || len(req.Events) != 1 {
		t.Fatalf("envelope: %+v", req)
	}
	if req.Events[0].To != "REDACTED" || req.Events[0].ToHMAC == "" || req.Events[0].From != "+13125550188" {
		t.Fatalf("event: %+v", req.Events[0])
	}

	c.APIKey = "k"
	_ = c.Ingest(context.Background(), []store.Event{ev})
	if gotAuth != "k" {
		t.Fatalf("X-Auth with key = %q", gotAuth)
	}
}
