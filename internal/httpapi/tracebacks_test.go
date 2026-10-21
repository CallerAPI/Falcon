package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/compliance"
	"github.com/callerapi/falcon/internal/store"
)

func inviteTo(from, to, callID string) string {
	return "INVITE sip:" + to + "@ex SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 203.0.113.40;branch=z9hG4bK1\r\n" +
		"From: <sip:" + from + "@ex>;tag=1\r\n" +
		"To: <sip:" + to + "@ex>\r\n" +
		"Call-ID: " + callID + "\r\nCSeq: 1 INVITE\r\nUser-Agent: Graystone-SBC/1.0\r\nContent-Length: 0\r\n\r\n"
}

// A request names a call. Falcon finds it, names the upstream, writes the
// answer, shows the clock on the home screen, and counts it in the report.
func TestTracebackFindsTheCallAndNamesTheUpstream(t *testing.T) {
	srv, db := newTestServer(t)
	srv.Compliance = &compliance.Autopilot{Store: db, Mode: srv.FCCMode, Reload: srv.ReloadRules}
	srv.Compliance.Apply(fccList())
	w := do(t, srv, http.MethodPost, "/v1/upstreams", map[string]any{"name": "Graystone", "rmd": "RMD0000002", "ips": []string{"203.0.113.0/24"}, "contact": "noc@graystone.example"})
	if w.Code != http.StatusCreated {
		t.Fatalf("upstream: %d %s", w.Code, w.Body.String())
	}
	callAt := time.Now().UTC().Truncate(time.Second)
	if w := do(t, srv, http.MethodPost, "/v1/screen", map[string]string{"switch": "t", "source_ip": "203.0.113.40", "raw_sip": inviteTo("+13125550100", "+14155550123", "tb-call-1")}); w.Code != http.StatusOK {
		t.Fatalf("screen: %d %s", w.Code, w.Body.String())
	}

	for _, bad := range []map[string]any{{"call_at": callAt.Format(time.RFC3339)}, {"from": "+13125550100", "call_at": "yesterday"}, {"from": "+13125550100", "call_at": callAt.Format(time.RFC3339), "window_minutes": 500}} {
		if w := do(t, srv, http.MethodPost, "/v1/tracebacks", bad); w.Code != http.StatusBadRequest {
			t.Fatalf("%v accepted: %d", bad, w.Code)
		}
	}
	w = do(t, srv, http.MethodPost, "/v1/tracebacks", map[string]any{
		"reference": "TB-2041", "from": "(312) 555-0100", "to": "4155550123", "call_at": callAt.Add(90 * time.Second).Format("2006-01-02 15:04:05"),
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("open: %d %s", w.Code, w.Body.String())
	}
	var c tracebackView
	_ = json.Unmarshal(w.Body.Bytes(), &c)
	if c.Upstream != "Graystone" || len(c.Calls) != 1 || c.Calls[0].CallID != "tb-call-1" || c.Status != store.TracebackOpen {
		t.Fatalf("case %+v", c)
	}
	if !strings.Contains(c.Answer, "We received this call from Graystone (RMD0000002)") || !strings.Contains(c.Answer, "noc@graystone.example") || !strings.Contains(c.Answer, "under FCC block order DA-26-1073") {
		t.Fatalf("answer:\n%s", c.Answer)
	}
	if got := c.DueAt.Sub(c.RequestedAt); got != 24*time.Hour {
		t.Fatalf("clock %s", got)
	}
	if !strings.Contains(c.PackURL, "/v1/traceback.zip?number=") {
		t.Fatalf("pack url %q", c.PackURL)
	}

	w = do(t, srv, http.MethodGet, "/v1/overview?range=24h", nil)
	var ov struct {
		Insights []Insight `json:"insights"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &ov)
	seen := false
	for _, in := range ov.Insights {
		if strings.HasPrefix(in.Key, "traceback:") {
			seen = strings.Contains(in.Title, "TB-2041") && strings.Contains(in.Detail, "Graystone")
		}
	}
	if !seen {
		t.Fatalf("no traceback item on the overview: %+v", ov.Insights)
	}

	w = do(t, srv, http.MethodPost, "/v1/tracebacks/"+jsonID(c.ID), map[string]any{"status": "answered", "answer": c.Answer + "Sent through the portal.\n"})
	if w.Code != http.StatusOK {
		t.Fatalf("answer: %d %s", w.Code, w.Body.String())
	}
	var done tracebackView
	_ = json.Unmarshal(w.Body.Bytes(), &done)
	if done.Status != store.TracebackAnswered || done.AnsweredAt == nil || !strings.HasSuffix(done.Answer, "Sent through the portal.") {
		t.Fatalf("answered case %+v", done.TracebackCase)
	}

	month := callAt.Format("2006-01")
	w = do(t, srv, http.MethodGet, "/v1/upstreams/report?month="+month, nil)
	var rep struct {
		Data []struct {
			Name       string `json:"name"`
			Calls      int    `json:"calls"`
			Tracebacks int    `json:"tracebacks"`
			Standing   string `json:"standing"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &rep)
	if len(rep.Data) != 1 || rep.Data[0].Name != "Graystone" || rep.Data[0].Calls != 1 || rep.Data[0].Tracebacks != 1 || rep.Data[0].Standing == "" {
		t.Fatalf("report %+v", rep.Data)
	}
	w = do(t, srv, http.MethodGet, "/v1/upstreams/report.csv?month="+month, nil)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Body.String(), "upstream,rmd_number,frn,fcc_standing,calls") || !strings.Contains(w.Body.String(), "Graystone,RMD0000002") {
		t.Fatalf("csv %d:\n%s", w.Code, w.Body.String())
	}
}

func TestTracebackWithNoMatchingCall(t *testing.T) {
	srv, _ := newTestServer(t)
	w := do(t, srv, http.MethodPost, "/v1/tracebacks", map[string]any{"from": "+13125550199", "call_at": time.Now().UTC().Format(time.RFC3339)})
	if w.Code != http.StatusCreated {
		t.Fatalf("open: %d %s", w.Code, w.Body.String())
	}
	var c tracebackView
	_ = json.Unmarshal(w.Body.Bytes(), &c)
	if len(c.EventIDs) != 0 || !strings.Contains(c.Answer, "We have no record of this call") {
		t.Fatalf("case %+v", c)
	}
}
