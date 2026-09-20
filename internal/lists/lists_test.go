package lists

import (
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	r, err := Normalize(Rule{Kind: Deny, Subject: Number, Value: " (415) 555-0100 "})
	if err != nil || r.Value != "+4155550100" {
		t.Fatalf("number: %+v %v", r, err)
	}
	r, err = Normalize(Rule{Kind: Allow, Subject: IP, Value: "203.0.113.77"})
	if err != nil || r.Value != "203.0.113.77/32" {
		t.Fatalf("ip: %+v %v", r, err)
	}
	r, err = Normalize(Rule{Kind: Allow, Subject: IP, Value: "203.0.113.77/24"})
	if err != nil || r.Value != "203.0.113.0/24" {
		t.Fatalf("cidr masked: %+v %v", r, err)
	}
	r, err = Normalize(Rule{Kind: Deny, Subject: SPC, Value: " 123a "})
	if err != nil || r.Value != "123A" {
		t.Fatalf("spc: %+v %v", r, err)
	}
	if _, err := Normalize(Rule{Kind: "maybe", Subject: Number, Value: "1"}); err == nil {
		t.Fatal("bad kind accepted")
	}
	if _, err := Normalize(Rule{Kind: Deny, Subject: IP, Value: "not-an-ip"}); err == nil {
		t.Fatal("bad ip accepted")
	}
}

func TestMatchDenyBeatsAllowAndLongestPrefix(t *testing.T) {
	now := time.Now()
	idx := NewIndex([]Rule{
		{ID: 1, Kind: Allow, Subject: IP, Value: "203.0.113.0/24"},
		{ID: 2, Kind: Deny, Subject: IP, Value: "203.0.113.128/25"},
		{ID: 3, Kind: Allow, Subject: Number, Value: "+14155550100"},
		{ID: 4, Kind: Deny, Subject: SPC, Value: "666A"},
		{ID: 5, Kind: Allow, Subject: Number, Value: "+15005550000", ExpiresAt: now.Add(-time.Minute)},
	}, now)
	if idx.Count() != 4 {
		t.Fatalf("expired rule counted: %d", idx.Count())
	}
	h, ok := idx.Match("+19999999999", "203.0.113.5", "")
	if !ok || h.ID != 1 {
		t.Fatalf("/24 allow: %+v %v", h, ok)
	}
	h, ok = idx.Match("+19999999999", "203.0.113.200", "")
	if !ok || h.ID != 2 {
		t.Fatalf("/25 deny must win: %+v %v", h, ok)
	}
	h, ok = idx.Match("14155550100", "198.51.100.1", "")
	if !ok || h.ID != 3 {
		t.Fatalf("number allow without plus: %+v %v", h, ok)
	}
	h, ok = idx.Match("+14155550100", "198.51.100.1", "666a")
	if !ok || h.ID != 4 {
		t.Fatalf("spc deny must beat number allow: %+v %v", h, ok)
	}
	if _, ok := idx.Match("+15005550000", "192.0.2.1", ""); ok {
		t.Fatal("expired rule matched")
	}
	if _, ok := idx.Match("", "", ""); ok {
		t.Fatal("empty input matched")
	}
}
