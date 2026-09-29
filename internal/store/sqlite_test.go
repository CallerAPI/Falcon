package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
)

func TestSQLiteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenSQLite(filepath.Join(dir, "falcon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	id, err := s.Insert(ctx, Event{
		ReceivedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Action:     score.ActionReject,
		RiskScore:  90,
		SourceIP:   "198.51.100.20",
		From:       "+14155550100",
		To:         "+15551212",
		CallID:     "abc",
		UserAgent:  "friendly-scanner",
		Reasons:    []score.Reason{{Code: "scanner_user_agent", Weight: 90, Category: "ua"}},
		RawSIP:     "INVITE sip:x SIP/2.0\n",
		Switch:     "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Action != score.ActionReject || got.From != "+14155550100" || got.RawSIP == "" {
		t.Fatalf("get %+v", got)
	}
	recent, err := s.Recent(ctx, 10)
	if err != nil || len(recent) != 1 {
		t.Fatalf("recent %v %v", recent, err)
	}
	st, err := s.Stats(ctx, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 1 || st.ByAction["reject"] != 1 {
		t.Fatalf("stats %+v", st)
	}
	pending, err := s.Unexported(ctx, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("unexported %v %v", pending, err)
	}
	if err := s.MarkExported(ctx, []int64{id}); err != nil {
		t.Fatal(err)
	}
	pending, err = s.Unexported(ctx, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("after mark %v %v", pending, err)
	}
	if err := s.KVSet(ctx, "share_opt_out", "1"); err != nil {
		t.Fatal(err)
	}
	v, err := s.KVGet(ctx, "share_opt_out")
	if err != nil || v != "1" {
		t.Fatalf("kv %q %v", v, err)
	}
}

func TestDirectionFilter(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "falcon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	for _, dir := range []string{"inbound", "outbound", ""} {
		if _, err := s.Insert(ctx, Event{Action: score.ActionAllow, Direction: dir, CallID: dir}); err != nil {
			t.Fatal(err)
		}
	}
	in, err := s.Query(ctx, Filter{Direction: "inbound", Limit: 10})
	if err != nil || len(in) != 2 {
		t.Fatalf("inbound %+v %v", in, err)
	}
	out, err := s.Query(ctx, Filter{Direction: "outbound", Limit: 10})
	if err != nil || len(out) != 1 || out[0].Direction != "outbound" {
		t.Fatalf("outbound %+v %v", out, err)
	}
	both, err := s.Query(ctx, Filter{Action: "allow", Direction: "outbound", Limit: 10})
	if err != nil || len(both) != 1 {
		t.Fatalf("stacked %+v %v", both, err)
	}
}

func TestSuspectsRanksHeldCallers(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "falcon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	rows := []Event{
		{ReceivedAt: now, Action: score.ActionAllow, RiskScore: 5, From: "+15120000001", To: "+19150000001", Direction: "outbound", CallID: "quiet"},
		{ReceivedAt: now, Action: score.ActionFlag, RiskScore: 45, From: "+15125758227", To: "+19152953172", Direction: "outbound", CallID: "hot-1", Reasons: []score.Reason{{Code: "invite_no_sdp", Weight: 5}, {Code: "caller_fanout", Weight: 40}}},
		{ReceivedAt: now, Action: score.ActionFlag, RiskScore: 45, From: "+15125758227", To: "+16185474997", Direction: "outbound", CallID: "hot-2", Reasons: []score.Reason{{Code: "caller_fanout", Weight: 40}}},
		{ReceivedAt: now, Action: score.ActionReject, RiskScore: 80, From: "+18005550199", To: "+19150000002", Direction: "inbound", CallID: "drop"},
	}
	for _, ev := range rows {
		if _, err := s.Insert(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Suspects(ctx, now.Add(-time.Hour), now.Add(time.Hour), "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Number != "+18005550199" || got[0].MaxScore != 80 || got[1].Number != "+15125758227" || got[1].Destinations != 2 || got[1].Outbound != 2 {
		t.Fatalf("rank %+v", got)
	}
	if len(got[1].Reasons) < 2 || got[1].Reasons[0].Code != "caller_fanout" || got[1].Reasons[0].Weight != 80 || got[1].Reasons[1].Code != "invite_no_sdp" {
		t.Fatalf("reasons %+v", got[1].Reasons)
	}
	out, err := s.Suspects(ctx, now.Add(-time.Hour), now.Add(time.Hour), "outbound", 10)
	if err != nil || len(out) != 1 || out[0].Number != "+15125758227" {
		t.Fatalf("outbound %+v %v", out, err)
	}
}

func TestTranscriptSearchAndVoiceScamTag(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "falcon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	id, err := s.Insert(ctx, Event{ReceivedAt: now, Action: score.ActionFlag, RiskScore: 45, From: "+15125758227", CallID: "said-cards", Direction: "outbound"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddVoiceSample(ctx, VoiceSample{EventID: id, CallID: "said-cards", Transcript: "pay with gift cards now", Category: "Tax Collection", Score: 0.93, Summary: "demands gift cards"}); err != nil {
		t.Fatal(err)
	}
	found, err := s.Query(ctx, Filter{Q: "gift cards", Limit: 10})
	if err != nil || len(found) != 1 || found[0].ID != id {
		t.Fatalf("search %+v %v", found, err)
	}
	if err := s.NoteVoiceScam(ctx, id, "Tax Collection", 0.93, "demands gift cards"); err != nil {
		t.Fatal(err)
	}
	if err := s.NoteVoiceScam(ctx, id, "Tax Collection", 0.93, "again"); err != nil {
		t.Fatal(err)
	}
	ev, err := s.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, reason := range ev.Reasons {
		if reason.Code == "voice_scam" {
			n++
			if reason.Weight != 0 || !strings.Contains(reason.Detail, "93%") {
				t.Fatalf("tag %+v", reason)
			}
		}
	}
	if n != 1 || ev.RiskScore != 45 {
		t.Fatalf("event %+v tags %d", ev, n)
	}
}
