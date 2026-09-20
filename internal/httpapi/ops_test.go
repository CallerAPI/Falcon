package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/alerts"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

func TestAuditRecordsMutationsWithActor(t *testing.T) {
	srv, _ := newTestServer(t)
	if w := do(t, srv, http.MethodPost, "/v1/rules", map[string]any{"kind": "deny", "subject": "spc", "value": "8080", "note": "test"}); w.Code != http.StatusCreated {
		t.Fatalf("add rule: %d %s", w.Code, w.Body.String())
	}
	if w := do(t, srv, http.MethodPut, "/v1/settings", map[string]int{"retention_days": 45}); w.Code != 200 {
		t.Fatalf("settings: %d", w.Code)
	}
	w := do(t, srv, http.MethodGet, "/v1/audit", nil)
	var got struct {
		Data []store.AuditEntry `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if len(got.Data) != 2 {
		t.Fatalf("audit entries = %d: %+v", len(got.Data), got.Data)
	}
	if got.Data[0].Action != "settings" || got.Data[1].Action != "rule.add" {
		t.Fatalf("order/actions: %+v", got.Data)
	}
	if !strings.HasPrefix(got.Data[1].Actor, "token@") || !strings.Contains(got.Data[1].Subject, "deny spc 8080") {
		t.Fatalf("actor/subject: %+v", got.Data[1])
	}
}

func TestAlertSettingsRoundTripAndTest(t *testing.T) {
	srv, _ := newTestServer(t)
	var hits int
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer hook.Close()
	srv.Alerts = &alerts.Watcher{Sources: alerts.Sources{Store: srv.Store, Thresholds: srv.AlertThresholds}}

	w := do(t, srv, http.MethodPut, "/v1/alerts/settings", map[string]any{"alert_webhook_url": hook.URL, "alert_signer_reject_pct": 40})
	if w.Code != 200 {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	th := srv.AlertThresholds(context.Background())
	if th.WebhookURL != hook.URL || th.SignerRejectPct != 40 || th.MinCalls != alerts.Defaults().MinCalls {
		t.Fatalf("thresholds: %+v", th)
	}
	if w := do(t, srv, http.MethodPost, "/v1/alerts/test", nil); w.Code != 200 || hits != 1 {
		t.Fatalf("test alert: %d hits=%d %s", w.Code, hits, w.Body.String())
	}
	if w := do(t, srv, http.MethodPut, "/v1/alerts/settings", map[string]any{"alert_webhook_url": "ftp://x"}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad scheme accepted: %d", w.Code)
	}
	w = do(t, srv, http.MethodGet, "/v1/audit", nil)
	if !strings.Contains(w.Body.String(), `\"alert_webhook_url\":\"set\"`) {
		t.Fatalf("audit must not carry the webhook url: %s", w.Body.String())
	}
}

func TestTracebackPackCarriesEventsAndRawSIP(t *testing.T) {
	srv, db := newTestServer(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, err := db.Insert(ctx, store.Event{
			ReceivedAt: time.Now().UTC(), Action: score.ActionReject, RiskScore: 90,
			From: "+13125550188", To: "+14155550100", SourceIP: "203.0.113.9",
			SignerSPC: "8080", SignerName: "Kestrel Gateway", Verstat: "TN-Validation-Failed",
			RawSIP: "INVITE sip:+14155550100@x SIP/2.0\r\nFrom: <sip:+13125550188@y>\r\n\r\n",
			Shaken: json.RawMessage(`{"x5u":"https://cert.example/k.pem"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if w := do(t, srv, http.MethodGet, "/v1/traceback.zip", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("no filter accepted: %d", w.Code)
	}
	w := do(t, srv, http.MethodGet, "/v1/traceback.zip?spc=8080", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("zip: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		names[f.Name] = string(b)
	}
	for _, want := range []string{"summary.json", "events.csv", "events.json", "README.txt"} {
		if _, ok := names[want]; !ok {
			t.Fatalf("missing %s in %v", want, keys(names))
		}
	}
	sipFiles := 0
	for n := range names {
		if strings.HasPrefix(n, "sip/") {
			sipFiles++
		}
	}
	if sipFiles != 3 {
		t.Fatalf("sip files = %d", sipFiles)
	}
	if !strings.Contains(names["events.csv"], "+13125550188") || !strings.Contains(names["events.csv"], "https://cert.example/k.pem") {
		t.Fatalf("csv: %s", names["events.csv"])
	}
	var summary map[string]any
	_ = json.Unmarshal([]byte(names["summary.json"]), &summary)
	if summary["events"].(float64) != 3 {
		t.Fatalf("summary: %v", summary)
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
