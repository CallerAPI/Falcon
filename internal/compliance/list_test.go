package compliance

import (
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/store"
)

func day(s string) *time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return &t
}

// testList holds fictional providers in every standing.
func testList() List {
	return List{GeneratedAt: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC), Providers: []Provider{
		{RMD: "RMD0000001", FRN: "0001110001", Name: "Northwind Voice LLC", Listed: true},
		{RMD: "RMD0000002", FRN: "0001110002", Name: "Graystone Gateway LLC", Order: OrderBlock, OrderDoc: "DA-26-1073", OrderDate: "2026-10-05"},
		{RMD: "RMD0000003", FRN: "0001110003", Name: "Harborline Telecom LLC", DBA: "Harbor Connect", Order: OrderRemoval, OrderDoc: "DA-25-694", OrderDate: "2025-08-06"},
		{RMD: "RMD0000004", FRN: "0001110004", Name: "Lakeshore Wholesale Inc", DelistedAt: day("2026-09-30")},
		// One company that refiled: the old filing is gone, the new one is listed.
		{RMD: "RMD0000005", FRN: "0001110005", Name: "Bluepeak Communications Inc", DelistedAt: day("2026-01-02")},
		{RMD: "RMD0000006", FRN: "0001110005", Name: "Bluepeak Communications Inc", Listed: true},
		// One FRN with an order on one filing and a clean listing on another.
		{RMD: "RMD0000007", FRN: "0001110007", Name: "Cobalt Route LLC", Order: OrderRemoval, OrderDoc: "DA-26-872", OrderDate: "2026-09-02"},
		{RMD: "RMD0000008", FRN: "0001110007", Name: "Cobalt Route Wholesale LLC", Listed: true},
	}}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{"RMD0012345": "RMD0012345", " rmd 12345 ": "RMD0012345", "12345": "RMD0012345", "RMD12345678": "", "RMDx": "", "": ""} {
		if got := NormalizeRMD(in); got != want {
			t.Errorf("NormalizeRMD(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"0012345678": "0012345678", "12345678": "0012345678", "001-234-5678": "0012345678", "12345678901": "", "": ""} {
		if got := NormalizeFRN(in); got != want {
			t.Errorf("NormalizeFRN(%q) = %q, want %q", in, got, want)
		}
	}
	if NormalizeName("Graystone Gateway, L.L.C.") != NormalizeName("GRAYSTONE GATEWAY LLC") {
		t.Fatal("corporate words and punctuation must fold away")
	}
}

func TestCheck(t *testing.T) {
	ix := NewIndex(testList())
	cases := []struct {
		name      string
		up        store.Upstream
		standing  string
		confirmed bool
		since     string
	}{
		{"listed by rmd", store.Upstream{Name: "x", RMD: "rmd0000001"}, Listed, true, ""},
		{"block order by rmd", store.Upstream{Name: "x", RMD: "RMD0000002"}, Blocked, true, "2026-10-05"},
		{"removal order by frn", store.Upstream{Name: "x", FRN: "1110003"}, Removed, true, "2025-08-06"},
		{"delisted", store.Upstream{Name: "x", RMD: "RMD0000004"}, Unlisted, true, "2026-09-30"},
		{"refiled company stays listed", store.Upstream{Name: "x", FRN: "0001110005"}, Listed, true, ""},
		{"order and clean listing on one frn", store.Upstream{Name: "x", FRN: "0001110007"}, Removed, false, "2026-09-02"},
		{"rmd not on the list", store.Upstream{Name: "x", RMD: "RMD0099999"}, NotFound, false, ""},
		{"frn not on the list", store.Upstream{Name: "x", FRN: "0009999999"}, NotFound, false, ""},
		{"name only", store.Upstream{Name: "Graystone Gateway"}, Blocked, false, "2026-10-05"},
		{"dba name only", store.Upstream{Name: "Harbor Connect, Inc."}, Removed, false, "2025-08-06"},
		{"unknown", store.Upstream{Name: "Nobody Telecom"}, Unknown, false, ""},
		{"rmd wins over a matching name", store.Upstream{Name: "Graystone Gateway", RMD: "RMD0000001"}, Listed, true, ""},
	}
	for _, c := range cases {
		r := ix.Check(c.up)
		if r.Standing != c.standing || r.Confirmed != c.confirmed || r.Since != c.since {
			t.Errorf("%s: got %s confirmed=%v since=%q, want %s confirmed=%v since=%q", c.name, r.Standing, r.Confirmed, r.Since, c.standing, c.confirmed, c.since)
		}
		if r.Blocks() != (c.confirmed && Bad(c.standing)) {
			t.Errorf("%s: Blocks() = %v", c.name, r.Blocks())
		}
	}
}

func TestSignerByName(t *testing.T) {
	ix := NewIndex(testList())
	r, ok := ix.ByName("GRAYSTONE GATEWAY, LLC")
	if !ok || r.Standing != Blocked || r.Confirmed {
		t.Fatalf("signer %+v %v", r, ok)
	}
	if _, ok := ix.ByName("Unrelated Carrier"); ok {
		t.Fatal("matched an unknown signer")
	}
}

func TestNormalizeUpstream(t *testing.T) {
	u, err := NormalizeUpstream(store.Upstream{Name: " Graystone ", RMD: "rmd 2", FRN: "1110002", IPs: []string{"192.0.2.7", "192.0.2.0/24", "192.0.2.7"}, SPCs: []string{" 123j "}})
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "Graystone" || u.RMD != "RMD0000002" || u.FRN != "0001110002" {
		t.Fatalf("normalized %+v", u)
	}
	if len(u.IPs) != 2 || u.IPs[0] != "192.0.2.7/32" || u.IPs[1] != "192.0.2.0/24" || len(u.SPCs) != 1 || u.SPCs[0] != "123J" {
		t.Fatalf("addresses %v, signer codes %v", u.IPs, u.SPCs)
	}
	for _, bad := range []store.Upstream{
		{Name: ""},
		{Name: "x", RMD: "RMD12345678"},
		{Name: "x", FRN: "12345678901"},
		{Name: "x", IPs: []string{"not an address"}},
		{Name: "x", SPCs: []string{"12-4"}},
	} {
		if _, err := NormalizeUpstream(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestUpstreamIndexLongestPrefix(t *testing.T) {
	ix := NewUpstreamIndex([]store.Upstream{
		{ID: 1, Name: "wide", IPs: []string{"192.0.2.0/24"}},
		{ID: 2, Name: "narrow", IPs: []string{"192.0.2.128/25"}, SPCs: []string{"123J"}},
	})
	if u, ok := ix.Find("192.0.2.200", ""); !ok || u.ID != 2 {
		t.Fatalf("got %+v %v", u, ok)
	}
	if u, ok := ix.Find("192.0.2.10", ""); !ok || u.ID != 1 {
		t.Fatalf("got %+v %v", u, ok)
	}
	if u, ok := ix.Find("203.0.113.1", "123j"); !ok || u.ID != 2 {
		t.Fatalf("signer lookup got %+v %v", u, ok)
	}
	if _, ok := ix.Find("203.0.113.1", ""); ok {
		t.Fatal("matched an unknown address")
	}
	var none *UpstreamIndex
	if _, ok := none.Find("192.0.2.1", ""); ok {
		t.Fatal("a nil index matched")
	}
}
