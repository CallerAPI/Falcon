package store

import (
	"context"
	"path/filepath"
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
