package demo

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/store"
)

func TestSeedAndSwapDistinguishFreeAndPaid(t *testing.T) {
	dir := Dir("")
	if !fileOK(IntelPath(dir, ProfilePaid)) {
		t.Fatalf("fixtures missing under %s", dir)
	}
	tmp := t.TempDir()
	copyFixtures(t, dir, tmp)
	if err := Seed(tmp); err != nil {
		t.Fatal(err)
	}
	free := open(t, DBPath(tmp, ProfileFree))
	paid := open(t, DBPath(tmp, ProfilePaid))
	defer free.Close()
	defer paid.Close()

	ctx := context.Background()
	end := time.Now().UTC()
	start := end.Add(-30 * 24 * time.Hour)
	freeStats, err := free.Stats(ctx, start, end)
	if err != nil {
		t.Fatal(err)
	}
	paidStats, err := paid.Stats(ctx, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if freeStats.Total < 2000 || paidStats.Total < 2000 {
		t.Fatalf("expected 30 days of traffic, free=%d paid=%d", freeStats.Total, paidStats.Total)
	}
	if freeStats.Total != paidStats.Total {
		t.Fatalf("profiles must share the same calls, free=%d paid=%d", freeStats.Total, paidStats.Total)
	}
	if paidStats.ByAction["reject"] <= freeStats.ByAction["reject"] {
		t.Fatalf("paid should reject more (feed + overlay), free reject=%d paid reject=%d", freeStats.ByAction["reject"], paidStats.ByAction["reject"])
	}

	freeProv, err := free.Parties(ctx, "provider", start, end, 50)
	if err != nil {
		t.Fatal(err)
	}
	paidProv, err := paid.Parties(ctx, "provider", start, end, 50)
	if err != nil {
		t.Fatal(err)
	}
	if hasProvider(freeProv, "8x8, Inc.") || hasProvider(freeProv, "Zoom Voice Communications, Inc.") {
		t.Fatal("free overlay must not name official CPaaS")
	}
	if !hasProvider(paidProv, "8x8, Inc.") || !hasProvider(paidProv, "Zoom Voice Communications, Inc.") {
		t.Fatalf("paid overlay missing CPaaS names: %#v", names(paidProv))
	}
	if !hasProvider(freeProv, "Datacenter") {
		t.Fatalf("free overlay should show Datacenter, got %#v", names(freeProv))
	}

	live := filepath.Join(tmp, "live.db")
	if _, err := Swap(tmp, live, ProfilePaid); err != nil {
		t.Fatal(err)
	}
	liveDB := open(t, live)
	defer liveDB.Close()
	got, err := liveDB.KVGet(ctx, "demo_profile")
	if err != nil || got != ProfilePaid {
		t.Fatalf("swapped profile = %q err=%v", got, err)
	}
}

func open(t *testing.T, path string) *store.SQLite {
	t.Helper()
	db, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func hasProvider(rows []store.Party, name string) bool {
	for _, p := range rows {
		if p.Name == name {
			return true
		}
	}
	return false
}

func names(rows []store.Party) []string {
	out := make([]string, 0, len(rows))
	for _, p := range rows {
		out = append(out, p.Name)
	}
	return out
}

func TestDecodeSwapRejectsHTML(t *testing.T) {
	resp := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("<!doctype html>"))}
	if err := decodeSwap(resp); err == nil {
		t.Fatal("HTML 200 must not count as a swap")
	}
	resp = &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"profile":"paid"}`))}
	if err := decodeSwap(resp); err != nil {
		t.Fatal(err)
	}
}

func copyFixtures(t *testing.T, src, dest string) {
	t.Helper()
	for _, name := range []string{"ipintel-free.csv", "ipintel-paid.csv", "spam_dids.txt"} {
		b, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dest, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
