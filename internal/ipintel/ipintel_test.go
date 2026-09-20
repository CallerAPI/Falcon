package ipintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sample = `cidr,provider,risk,tags,source
# comment line
203.0.113.0/24,Example Wholesale,neutral,carrier|us,callerapi
203.0.113.128/25,Example Gateway LLC,hostile,gateway;attest-c,callerapi
198.51.100.7,Known Scanner Host,block,scanner,local
2001:db8::/32,Example v6 Carrier,trusted,,local
not-an-ip,Broken,neutral,,
`

func TestParseAndLongestPrefix(t *testing.T) {
	idx := newIndex()
	n, err := Parse(strings.NewReader(sample), idx)
	if n != 4 {
		t.Fatalf("added %d rows", n)
	}
	if err == nil || !strings.Contains(err.Error(), "1 rows skipped") {
		t.Fatalf("expected one skipped row, got %v", err)
	}
	tbl := New("", "", "", time.Hour)
	tbl.v4, tbl.v6, tbl.count = idx.v4, idx.v6, idx.count

	m, ok := tbl.Lookup("203.0.113.5")
	if !ok || m.Provider != "Example Wholesale" || m.Risk != RiskNeutral {
		t.Fatalf("/24 match: %+v %v", m, ok)
	}
	m, ok = tbl.Lookup("203.0.113.200")
	if !ok || m.Provider != "Example Gateway LLC" || m.Risk != RiskHostile {
		t.Fatalf("/25 should win over /24: %+v %v", m, ok)
	}
	if len(m.Tags) != 2 || m.Tags[0] != "gateway" || m.Tags[1] != "attest-c" {
		t.Fatalf("tags: %v", m.Tags)
	}
	m, ok = tbl.Lookup("198.51.100.7")
	if !ok || m.Risk != RiskBlock {
		t.Fatalf("host row: %+v %v", m, ok)
	}
	if _, ok := tbl.Lookup("198.51.100.8"); ok {
		t.Fatal("neighbour of a /32 must not match")
	}
	m, ok = tbl.Lookup("2001:db8:1::9")
	if !ok || m.Risk != RiskTrusted {
		t.Fatalf("v6: %+v %v", m, ok)
	}
	if _, ok := tbl.Lookup("::ffff:203.0.113.5"); !ok {
		t.Fatal("mapped v4 must unmap before lookup")
	}
	if _, ok := tbl.Lookup("garbage"); ok {
		t.Fatal("unparseable ip must miss")
	}
}

func TestLoadMergesURLAndFileWithFileWinning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("cidr,provider,risk\n203.0.113.0/24,Hosted Name,suspicious\n192.0.2.0/24,Hosted Only,neutral\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "ipintel.csv")
	if err := os.WriteFile(path, []byte("203.0.113.0/24,Local Override,trusted\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tbl := New(path, srv.URL, "k", time.Hour)
	tbl.Load(context.Background())
	count, loadedAt, lastErr := tbl.Status()
	if count != 2 || loadedAt.IsZero() || lastErr != "" {
		t.Fatalf("status: %d %v %q", count, loadedAt, lastErr)
	}
	m, _ := tbl.Lookup("203.0.113.9")
	if m.Provider != "Local Override" || m.Risk != RiskTrusted {
		t.Fatalf("file must override url: %+v", m)
	}
	if m, ok := tbl.Lookup("192.0.2.1"); !ok || m.Provider != "Hosted Only" {
		t.Fatalf("hosted row missing: %+v %v", m, ok)
	}
}

func TestLoadKeepsOldTableWhenEverySourceFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	tbl := New("", srv.URL, "", time.Hour)
	idx := newIndex()
	_, _ = Parse(strings.NewReader("203.0.113.0/24,Old,neutral\n"), idx)
	tbl.v4, tbl.count = idx.v4, idx.count

	tbl.Load(context.Background())
	if _, ok := tbl.Lookup("203.0.113.1"); !ok {
		t.Fatal("a failed reload must not empty the table")
	}
	if _, _, lastErr := tbl.Status(); lastErr == "" {
		t.Fatal("error must be recorded")
	}
}

func TestParseRisk(t *testing.T) {
	cases := map[string]Risk{"": RiskNeutral, "TRUSTED": RiskTrusted, "watch": RiskSuspicious, "abuse": RiskHostile, "deny": RiskBlock, "weird": RiskNeutral}
	for in, want := range cases {
		if got := ParseRisk(in); got != want {
			t.Fatalf("ParseRisk(%q)=%q want %q", in, got, want)
		}
	}
}
