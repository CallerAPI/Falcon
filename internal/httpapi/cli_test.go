package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/feed"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

const ukMobile = "+447700900123"

func ukInvite(from, privacy, pai string) ScreenRequest {
	headers := map[string]string{
		"From":         "<sip:" + from + "@203.0.113.9>;tag=1",
		"To":           "<sip:+14155550100@x>",
		"Call-ID":      "uk-" + from,
		"User-Agent":   "desk",
		"Max-Forwards": "70",
		"Content-Type": "application/sdp",
		"Diversion":    "<sip:" + ukMobile + "@fwd>",
		"History-Info": "<sip:" + ukMobile + "@fwd>;index=1",
	}
	if privacy != "" {
		headers["Privacy"] = privacy
	}
	if pai != "" {
		headers["P-Asserted-Identity"] = "<sip:" + pai + "@net>"
	}
	return ScreenRequest{
		Method: "INVITE", RequestURI: "sip:+14155550100@x", SourceIP: "203.0.113.9",
		Headers: headers, Body: "v=0\r\no=- 0 0 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\n",
	}
}

func TestUKMobileScreenRecordsAndDoesNotBlock(t *testing.T) {
	srv, db := newTestServer(t)
	ctx := context.Background()
	if w := do(t, srv, http.MethodPost, "/v1/rules", map[string]string{"kind": "international", "subject": "ip", "value": "203.0.113.9", "note": "gateway"}); w.Code != http.StatusCreated {
		t.Fatalf("rule: %d %s", w.Code, w.Body.String())
	}
	if w := do(t, srv, http.MethodPost, "/v1/rules", map[string]string{"kind": "international", "subject": "number", "value": ukMobile}); w.Code != http.StatusBadRequest {
		t.Fatalf("number peer accepted: %d %s", w.Code, w.Body.String())
	}
	if w := do(t, srv, http.MethodPost, "/v1/rules", map[string]string{"kind": "exempt", "subject": "ip", "value": "203.0.113.10", "note": "roaming"}); w.Code != http.StatusCreated {
		t.Fatalf("exempt: %d %s", w.Code, w.Body.String())
	}

	res, err := srv.Screen(ctx, ukInvite(ukMobile, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(res, score.ReasonUKMobileFromAbroad) {
		t.Fatalf("reasons %+v", res.Reasons)
	}
	if res.Action == score.ActionReject || res.Headers[score.HeaderCLIWithhold] != "" {
		t.Fatalf("default changed the call: %s header %q score %d", res.Action, res.Headers[score.HeaderCLIWithhold], res.RiskScore)
	}
	for _, r := range res.Reasons {
		if r.Code == score.ReasonUKMobileFromAbroad && r.Weight != 0 {
			t.Fatalf("weight %d", r.Weight)
		}
	}

	other := ukInvite(ukMobile, "", "")
	other.SourceIP = "203.0.113.10"
	res, err = srv.Screen(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	if hasReason(res, score.ReasonUKMobileFromAbroad) {
		t.Fatal("exempt peer was marked")
	}

	domestic := ukInvite("+14155550100", "", "")
	res, err = srv.Screen(ctx, domestic)
	if err != nil {
		t.Fatal(err)
	}
	if hasReason(res, score.ReasonUKMobileFromAbroad) {
		t.Fatal("Diversion was treated as the caller ID")
	}

	if w := do(t, srv, http.MethodPut, "/v1/settings", map[string]string{"cli_withhold": "nope"}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad setting accepted: %d", w.Code)
	}
	if w := do(t, srv, http.MethodPut, "/v1/settings", map[string]string{"cli_withhold": "enforce"}); w.Code != http.StatusOK {
		t.Fatalf("enforce: %d %s", w.Code, w.Body.String())
	}
	res, err = srv.Screen(ctx, ukInvite(ukMobile, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.Headers[score.HeaderCLIWithhold] != "1" || res.Action == score.ActionReject {
		t.Fatalf("enforce result %s header %q", res.Action, res.Headers[score.HeaderCLIWithhold])
	}

	if _, err := db.Insert(ctx, store.Event{
		ReceivedAt: time.Now().UTC(), Action: score.ActionAllow, From: ukMobile, To: "+14155550100", CallID: "counted",
		Reasons: []score.Reason{{Code: score.ReasonUKMobileFromAbroad, Weight: 0, Category: "identity"}},
	}); err != nil {
		t.Fatal(err)
	}
	w := do(t, srv, http.MethodGet, "/v1/overview?range=24h", nil)
	var ov Overview
	if err := json.Unmarshal(w.Body.Bytes(), &ov); err != nil {
		t.Fatal(err)
	}
	if ov.Totals.CLIWithhold < 1 || ov.Status.CLIWithhold != "enforce" {
		t.Fatalf("overview count %d mode %q", ov.Totals.CLIWithhold, ov.Status.CLIWithhold)
	}

	why := explain([]score.Reason{
		{Code: "missing_identity", Weight: 15},
		{Code: score.ReasonUKMobileFromAbroad, Weight: 0},
	})
	var saw bool
	for _, row := range why {
		if row.Code == score.ReasonUKMobileFromAbroad {
			saw = row.Text == "The caller ID is a UK mobile number on a call from outside the UK."
		}
	}
	if !saw {
		t.Fatalf("explain hid the reason: %+v", why)
	}
}

func TestWithheldCallUsesPAIForFeedAndReputationOnly(t *testing.T) {
	srv, _ := newTestServer(t)
	var lookups, bcid []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/lookup/") {
			lookups = append(lookups, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":{"is_spam":false,"spam_score":0}}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		bcid = append(bcid, string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"verdict":"verified","action":"allow","identity":{"verified":true,"name":"Drama","logo_url":"https://example.test/logo"}}}`)
	}))
	t.Cleanup(api.Close)
	srv.Cfg.CallerAPIKey = "k"
	srv.Cfg.SpamFeed = true
	srv.Cfg.VoiceFirewall = true
	srv.Cfg.BCID = true
	srv.Feed = feed.NewSpam(api.URL, "k", time.Hour)
	srv.Feed.LoadNumbers([]string{ukMobile})
	srv.Live = &feed.Live{BaseURL: api.URL, APIKey: "k", HTTP: api.Client()}

	ctx := context.Background()
	withheld := ukInvite("anonymous", "id", ukMobile)
	res, err := srv.Screen(ctx, withheld)
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != score.ActionReject || !hasReason(res, "spam_feed_hit") || hasReason(res, "from_pai_mismatch") {
		t.Fatalf("feed result %s %+v", res.Action, res.Reasons)
	}
	if res.Signals.From != "anonymous" {
		t.Fatalf("showed %q to the callee path", res.Signals.From)
	}
	blob, _ := json.Marshal(res.Headers)
	if strings.Contains(string(blob), "447700900123") || strings.Contains(res.Signals.From, "447700900123") {
		t.Fatalf("network number leaked into headers: %s from %s", blob, res.Signals.From)
	}
	if len(bcid) != 0 {
		t.Fatalf("display lookup ran on a withheld call: %v", bcid)
	}

	// A second check of the same number still calls the lookup.
	if _, err := srv.Screen(ctx, withheld); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range lookups {
		if strings.Contains(p, "447700900123") {
			n++
		}
		if strings.Contains(p, "anonymous") {
			t.Fatalf("lookup used the anonymous user: %v", lookups)
		}
	}
	if n != 2 {
		t.Fatalf("lookups = %v", lookups)
	}

	open := ukInvite("anonymous", "", ukMobile)
	res, err = srv.Screen(ctx, open)
	if err != nil {
		t.Fatal(err)
	}
	if hasReason(res, "spam_feed_hit") {
		t.Fatal("feed used PAI when the call was not withheld")
	}
	if !hasReason(res, "from_pai_mismatch") {
		t.Fatalf("expected mismatch: %+v", res.Reasons)
	}
}
