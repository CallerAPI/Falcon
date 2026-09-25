package fleet

import (
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/store"
)

func TestStaleSnapshotDoesNotChangeTheLocalCount(t *testing.T) {
	c := NewCache(time.Millisecond)
	c.Replace(map[string]store.Activity{"+14155550100": {Calls: 40, DistinctCallees: 40}})
	time.Sleep(5 * time.Millisecond)
	got := c.Merge("+14155550100", store.Activity{Calls: 2})
	if got.Calls != 2 {
		t.Fatalf("stale snapshot applied: %+v", got)
	}

	fresh := NewCache(time.Minute)
	fresh.Replace(map[string]store.Activity{"+14155550100": {Calls: 3, DistinctCallees: 3}})
	got = fresh.Merge("+14155550100", store.Activity{Calls: 2, DistinctCallees: 1})
	if got.Calls != 5 || got.DistinctCallees != 4 {
		t.Fatalf("fresh merge: %+v", got)
	}
	if fresh.Merge("+1999", store.Activity{Calls: 1}).Calls != 1 {
		t.Fatal("unknown caller changed")
	}
}
