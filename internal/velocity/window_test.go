package velocity

import (
	"testing"
	"time"
)

func TestHitAndUnique(t *testing.T) {
	w := New(time.Minute)
	now := time.Unix(1_700_000_000, 0)
	if n := w.Hit("ip:1.1.1.1", now); n != 1 {
		t.Fatalf("first hit %d", n)
	}
	if n := w.Hit("ip:1.1.1.1", now.Add(10*time.Second)); n != 2 {
		t.Fatalf("second hit %d", n)
	}
	if n := w.Hit("ip:1.1.1.1", now.Add(2*time.Minute)); n != 1 {
		t.Fatalf("after window %d", n)
	}
	if n := w.Unique("scan:1.1.1.1", "+1", now); n != 1 {
		t.Fatalf("unique %d", n)
	}
	if n := w.Unique("scan:1.1.1.1", "+2", now.Add(time.Second)); n != 2 {
		t.Fatalf("unique 2 %d", n)
	}
}
