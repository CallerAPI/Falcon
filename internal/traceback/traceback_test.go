package traceback

import (
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/store"
)

func TestVariants(t *testing.T) {
	cases := map[string][]string{
		"(312) 555-0100":   {"3125550100", "13125550100", "+13125550100"},
		"+1 312 555 0100":  {"3125550100", "13125550100", "+13125550100"},
		"+44 20 7946 0000": {"442079460000", "+442079460000"},
		"anonymous":        nil,
	}
	for in, want := range cases {
		got := Variants(in)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("Variants(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestPickTheNearestCall(t *testing.T) {
	at := time.Date(2026, 10, 21, 14, 3, 7, 0, time.UTC)
	evs := []store.Event{{ID: 1, ReceivedAt: at.Add(-8 * time.Minute)}, {ID: 2, ReceivedAt: at.Add(40 * time.Second)}, {ID: 3, ReceivedAt: at.Add(3 * time.Minute)}}
	if ev, ok := Pick(evs, at); !ok || ev.ID != 2 {
		t.Fatalf("picked %d", ev.ID)
	}
	if _, ok := Pick(nil, at); ok {
		t.Fatal("picked from nothing")
	}
}

func TestAnswer(t *testing.T) {
	at := time.Date(2026, 10, 21, 14, 3, 7, 0, time.UTC)
	c := store.TracebackCase{Reference: "TB-2041", From: "+13125550100", To: "+14155550123", CallAt: at, WindowS: 600}
	ev := store.Event{ReceivedAt: at.Add(2 * time.Second), SourceIP: "203.0.113.40", CallID: "a84b4c76e66710", Attest: "B", SignerSPC: "567J", SignerName: "Graystone Gateway LLC", Verstat: "TN-Validation-Passed"}
	up := store.Upstream{ID: 1, Name: "Graystone Gateway", RMD: "RMD0000002", Contact: "noc@graystone.example"}

	got := Answer(c, Found{Event: &ev, Upstream: &up, Standing: "under FCC block order DA-26-1073"})
	for _, want := range []string{"Traceback TB-2041: call from +13125550100 to +14155550123 at 2026-10-21 14:03:07 UTC.",
		"We received this call from Graystone Gateway (RMD0000002) at 2026-10-21 14:03:09 UTC, from address 203.0.113.40.",
		"Upstream traceback contact: noc@graystone.example.", "FCC standing of the upstream: under FCC block order DA-26-1073.",
		"Call-ID: a84b4c76e66710.", "STIR/SHAKEN: attestation B, signed by 567J (Graystone Gateway LLC), TN-Validation-Passed."} {
		if !strings.Contains(got, want) {
			t.Errorf("answer lacks %q:\n%s", want, got)
		}
	}
	unknown := Answer(c, Found{Event: &store.Event{ReceivedAt: at, SourceIP: "198.51.100.9"}})
	if !strings.Contains(unknown, "not in our upstream registry") || !strings.Contains(unknown, "was not signed") {
		t.Errorf("unregistered answer:\n%s", unknown)
	}
	out := Answer(c, Found{Event: &store.Event{ReceivedAt: at, Direction: "outbound", Customer: "acme"}})
	if !strings.Contains(out, "We originated this call for our customer acme") {
		t.Errorf("outbound answer:\n%s", out)
	}
	none := Answer(c, Found{RetentionDays: 30})
	if !strings.Contains(none, "We have no record of this call within 10m0s") || !strings.Contains(none, "last 30 days") {
		t.Errorf("no-call answer:\n%s", none)
	}
}

func TestReport(t *testing.T) {
	ups := []store.Upstream{{ID: 1, Name: "Graystone Gateway", RMD: "RMD0000002"}, {ID: 2, Name: "Northwind Voice"}, {ID: 3, Name: "Quiet Carrier"}}
	owner := func(ip, spc string) (store.Upstream, bool) {
		switch {
		case strings.HasPrefix(ip, "203.0.113."):
			return ups[0], true
		case ip == "198.51.100.10" || spc == "1234":
			return ups[1], true
		}
		return store.Upstream{}, false
	}
	traffic := []store.SourceTraffic{
		{SourceIP: "203.0.113.40", Calls: 100, Blocked: 40, SpamHits: 12},
		{SourceIP: "203.0.113.41", SPC: "567J", Calls: 50, Blocked: 10, Honeypots: 2},
		{SourceIP: "198.51.100.10", Calls: 500, Flagged: 5},
		{SourceIP: "192.0.2.200", Calls: 7, Blocked: 7},
	}
	cases := []store.TracebackCase{{UpstreamID: 1}, {UpstreamID: 1}, {UpstreamID: 0}}
	rows := Report(traffic, ups, owner, func(id int64) Standing {
		if id == 1 {
			return Standing{Code: "blocked", Confirmed: true, Text: "under FCC block order DA-26-1073"}
		}
		return Standing{}
	}, cases)
	if len(rows) != 4 {
		t.Fatalf("%d rows: %+v", len(rows), rows)
	}
	if r := rows[0]; r.ID != 1 || r.Calls != 150 || r.Blocked != 50 || r.SpamHits != 12 || r.Honeypots != 2 || r.Tracebacks != 2 || r.Standing != "blocked" || !r.Confirmed || r.StandingText == "" {
		t.Fatalf("first row %+v", r)
	}
	if r := rows[len(rows)-1]; r.ID != 0 || r.Name != Unregistered || r.Calls != 7 {
		t.Fatalf("the unregistered row must come last: %+v", r)
	}
	for _, r := range rows {
		if r.ID == 3 && r.Calls != 0 {
			t.Fatalf("quiet upstream %+v", r)
		}
	}
}
