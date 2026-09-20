package velocity

import (
	"sync"
	"time"
)

// Window counts events in a sliding interval. It is per-process.
// Run one Falcon next to each switch. Each node sees its own traffic.
type Window struct {
	mu      sync.Mutex
	window  time.Duration
	hits    map[string][]time.Time
	dests   map[string]map[string]time.Time
	maxKeys int
}

func New(window time.Duration) *Window {
	if window <= 0 {
		window = time.Minute
	}
	return &Window{
		window:  window,
		hits:    make(map[string][]time.Time),
		dests:   make(map[string]map[string]time.Time),
		maxKeys: 100_000,
	}
}

// Hit records a key and returns how many times it fired in the window.
func (w *Window) Hit(key string, now time.Time) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gcLocked(now)
	cut := now.Add(-w.window)
	times := w.hits[key]
	kept := times[:0]
	for _, t := range times {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	w.hits[key] = kept
	return len(kept)
}

// Unique records a secondary value under key and returns the distinct count.
func (w *Window) Unique(key, value string, now time.Time) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gcLocked(now)
	cut := now.Add(-w.window)
	set := w.dests[key]
	if set == nil {
		set = make(map[string]time.Time)
		w.dests[key] = set
	}
	for v, t := range set {
		if !t.After(cut) {
			delete(set, v)
		}
	}
	set[value] = now
	return len(set)
}

func (w *Window) gcLocked(now time.Time) {
	if len(w.hits)+len(w.dests) < w.maxKeys {
		return
	}
	cut := now.Add(-w.window)
	for k, times := range w.hits {
		alive := false
		for _, t := range times {
			if t.After(cut) {
				alive = true
				break
			}
		}
		if !alive {
			delete(w.hits, k)
		}
	}
	for k, set := range w.dests {
		for v, t := range set {
			if !t.After(cut) {
				delete(set, v)
			}
		}
		if len(set) == 0 {
			delete(w.dests, k)
		}
	}
}
