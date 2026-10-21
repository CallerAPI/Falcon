package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"time"

	"github.com/callerapi/falcon/internal/share"
	"github.com/callerapi/falcon/internal/store"
)

// Queue drains unexported events to S3 and/or CallerAPI.
type Queue struct {
	Store          store.Store
	S3             *S3
	CallerAPI      *CallerAPI
	CallerAPIReady func(context.Context) bool
	Interval       time.Duration
	// CleanEvery sends one clean inbound call in N in full as a sample.
	// Zero sends none. Every clean call is counted in the hourly rollup.
	CleanEvery int

	apiFailures int
	// pauseUntil holds the next CallerAPI attempt after a failure.
	pauseUntil time.Time
	now        func() time.Time
}

// batchSize is one export call. maxBatchesPerTick bounds one tick, so a
// carrier ingress at tens of calls a second drains between ticks instead
// of falling behind by a fixed 100 events every 30 s. maxBackoff caps the
// wait after failed posts.
const (
	batchSize         = 100
	maxBatchesPerTick = 50
	maxBackoff        = 15 * time.Minute
	defaultInterval   = 30 * time.Second
)

// An hour of clean calls is sent once, rollupDelay after it ends, so the
// outcomes of calls that ended late are in. A caller needs minCallerCalls
// clean calls in the hour to get its own row. CallerAPI takes at most
// maxRollupsPerPost rows in one post and keeps 7 days.
const (
	rollupDelay       = 10 * time.Minute
	minCallerCalls    = 3
	maxRollupsPerPost = 5000
	rollupMaxAge      = 7 * 24 * time.Hour
	kvRollupNext      = "telemetry_rollup_next"
)

func (q *Queue) Run(ctx context.Context) {
	if q.Interval <= 0 {
		q.Interval = defaultInterval
	}
	t := time.NewTicker(q.Interval)
	defer t.Stop()
	q.drain(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			q.drain(ctx)
		}
	}
}

// drain flushes until the backlog is below one batch or the per-tick cap
// is reached, then sends the hours of clean calls that are ready. A failed
// post stops the tick; the next one retries.
func (q *Queue) drain(ctx context.Context) {
	defer q.sendRollups(ctx)
	for i := 0; i < maxBatchesPerTick; i++ {
		if n := q.flush(ctx); n < batchSize {
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// flush exports one batch and returns how many events it marked. Zero
// means nothing waited or the export failed.
func (q *Queue) flush(ctx context.Context) int {
	wantS3 := q.S3 != nil && q.S3.Enabled()
	wantAPI := q.CallerAPI != nil && q.CallerAPI.Enabled() && (q.CallerAPIReady == nil || q.CallerAPIReady(ctx))
	if !wantS3 && !wantAPI {
		return 0
	}
	// S3 and CallerAPI share the exported mark, so a pause holds both.
	if wantAPI && q.clock().Before(q.pauseUntil) {
		return 0
	}
	events, err := q.Store.Unexported(ctx, batchSize)
	if err != nil || len(events) == 0 {
		return 0
	}

	if wantS3 {
		if err := q.putS3(ctx, events); err != nil {
			log.Printf("falcon export s3: %v", err)
			return 0
		}
	}
	if wantAPI {
		for i := range events {
			if !events[i].Sampled {
				continue
			}
			if v, ok, err := q.Store.VoiceSampleForEvent(ctx, events[i].ID); err == nil && ok && v.Category != "" {
				events[i].VoiceCategory, events[i].VoiceScore = v.Category, v.Score
			}
		}
		b := q.classify(events)
		if err := q.CallerAPI.Send(ctx, b); err != nil {
			q.fail(err, fmt.Sprintf("%d events in this batch", len(b.Events)))
			return 0
		}
		q.recovered()
	}
	ids := make([]int64, len(events))
	for i, ev := range events {
		ids[i] = ev.ID
	}
	if err := q.Store.MarkExported(ctx, ids); err != nil {
		log.Printf("falcon export mark: %v", err)
		return 0
	}
	return len(events)
}

// classify keeps each call with a signal as an evidence row and one clean
// inbound call in CleanEvery as a sample. The other clean calls travel in
// the hourly rollup. A clean outbound call is never sent.
func (q *Queue) classify(events []store.Event) Batch {
	var b Batch
	for _, ev := range events {
		switch {
		case share.Evidence(ev):
			b.Events, b.Kinds = append(b.Events, ev), append(b.Kinds, share.KindEvidence)
		case q.CleanEvery > 0 && ev.Direction != "outbound" && ev.ID%int64(q.CleanEvery) == 0:
			b.Events, b.Kinds = append(b.Events, ev), append(b.Kinds, share.KindSample)
		}
	}
	return b
}

// sendRollups sends every hour of clean calls that is ready and not sent.
// A resent hour replaces the stored one, so a failure only means a retry.
func (q *Queue) sendRollups(ctx context.Context) {
	if q.CallerAPI == nil || !q.CallerAPI.Enabled() || (q.CallerAPIReady != nil && !q.CallerAPIReady(ctx)) || q.clock().Before(q.pauseUntil) {
		return
	}
	now := q.clock().UTC()
	ready := now.Add(-time.Hour - rollupDelay).Truncate(time.Hour)
	next := ready
	if v, _ := q.Store.KVGet(ctx, kvRollupNext); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			next = t.UTC()
		}
	}
	if floor := now.Add(-rollupMaxAge).Truncate(time.Hour).Add(time.Hour); next.Before(floor) {
		next = floor
	}
	for !next.After(ready) {
		rows, err := q.Store.CleanRollups(ctx, next, next.Add(time.Hour), minCallerCalls)
		if err != nil {
			log.Printf("falcon telemetry: rollup %s: %v", next.Format(time.RFC3339), err)
			return
		}
		wire := wireRollups(next, rows)
		for start := 0; start < len(wire); start += maxRollupsPerPost {
			if err := q.CallerAPI.Send(ctx, Batch{Rollups: wire[start:min(start+maxRollupsPerPost, len(wire))]}); err != nil {
				q.fail(err, "rollup of "+next.Format("2006-01-02 15:00"))
				return
			}
		}
		q.recovered()
		next = next.Add(time.Hour)
		if err := q.Store.KVSet(ctx, kvRollupNext, next.Format(time.RFC3339)); err != nil {
			log.Printf("falcon telemetry: rollup mark: %v", err)
			return
		}
	}
}

func wireRollups(hour time.Time, rows []store.RollupRow) []share.Rollup {
	out := make([]share.Rollup, 0, len(rows))
	stamp := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	for _, r := range rows {
		out = append(out, share.Rollup{
			Hour: hour.UTC().Format(time.RFC3339), Dim: r.Dim, Key: r.Key, Label: share.SafeLabel(r.Label), SPC: r.SPC, Fingerprint: r.Fingerprint,
			Calls: r.Calls, Verified: r.Verified, Completed: r.Completed, Answered: r.Answered, TalkSeconds: r.TalkSeconds, Callees: r.Callees,
			FirstSeen: stamp(r.FirstSeen), LastSeen: stamp(r.LastSeen),
		})
	}
	return out
}

// fail pauses CallerAPI posts. An offline or air-gapped install would
// otherwise log on every attempt for the life of the process.
func (q *Queue) fail(err error, what string) {
	q.apiFailures++
	wait := q.backoff(err)
	q.pauseUntil = q.clock().Add(wait)
	if q.apiFailures == 1 || q.apiFailures%20 == 0 {
		log.Printf("falcon telemetry: %v (%d attempts, %s, next attempt in %s)", err, q.apiFailures, what, wait.Round(time.Second))
	}
}

func (q *Queue) recovered() {
	if q.apiFailures > 0 {
		log.Printf("falcon telemetry: reachable again after %d attempts", q.apiFailures)
		q.apiFailures = 0
	}
}

// backoff is the wait before the next CallerAPI attempt. A Retry-After from
// the server wins. Otherwise the wait doubles from one interval up to
// maxBackoff. Jitter keeps a fleet of installs from retrying in step.
func (q *Queue) backoff(err error) time.Duration {
	var he *HTTPError
	if errors.As(err, &he) && he.RetryAfter > 0 {
		wait := min(he.RetryAfter, maxBackoff)
		return wait + time.Duration(rand.Int64N(int64(wait/5)+1))
	}
	wait := q.Interval
	if wait <= 0 {
		wait = defaultInterval
	}
	for i := 1; i < q.apiFailures && wait < maxBackoff; i++ {
		wait *= 2
	}
	wait = min(wait, maxBackoff)
	return wait - time.Duration(rand.Int64N(int64(wait/5)+1))
}

func (q *Queue) clock() time.Time {
	if q.now != nil {
		return q.now()
	}
	return time.Now()
}

func (q *Queue) putS3(ctx context.Context, events []store.Event) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	key := now.Format("dt=2006-01-02/hour=15/") + now.Format("20060102T150405") + ".jsonl"
	return q.S3.Put(ctx, key, buf.Bytes(), "application/x-ndjson")
}
