package store

import (
	"context"
	"log"
	"time"
)

// Retention is the pair of windows the janitor enforces.
type Retention struct {
	// Events is how long a decision row lives.
	Events time.Duration
	// RawSIP is how long the raw message stays on a row before it is
	// blanked. Zero keeps it for the life of the row.
	RawSIP time.Duration
}

// Janitor prunes old events and scrubs raw SIP once an hour, reading the
// current retention each time so a change in the dashboard takes effect
// without a restart.
func Janitor(ctx context.Context, s Store, current func() Retention) {
	run := func() {
		r := current()
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		if r.RawSIP > 0 {
			n, err := s.ScrubRawSIP(cctx, time.Now().Add(-r.RawSIP))
			if err != nil {
				log.Printf("falcon janitor: scrub: %v", err)
			} else if n > 0 {
				log.Printf("falcon janitor: scrubbed raw SIP from %d events older than %s", n, r.RawSIP)
			}
		}
		if r.Events > 0 {
			n, err := s.Prune(cctx, time.Now().Add(-r.Events))
			if err != nil {
				log.Printf("falcon janitor: prune: %v", err)
			} else if n > 0 {
				log.Printf("falcon janitor: pruned %d events older than %s", n, r.Events)
			}
		}
	}
	run()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
