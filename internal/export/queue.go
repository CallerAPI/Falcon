package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"math/rand/v2"
	"time"

	"github.com/callerapi/falcon/internal/store"
)

// Queue drains unexported events to S3 and/or CallerAPI.
type Queue struct {
	Store          store.Store
	S3             *S3
	CallerAPI      *CallerAPI
	CallerAPIReady func(context.Context) bool
	Interval       time.Duration

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
// is reached. A failed flush stops the tick; the next one retries.
func (q *Queue) drain(ctx context.Context) {
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
		if err := q.CallerAPI.Ingest(ctx, events); err != nil {
			q.apiFailures++
			wait := q.backoff(err)
			q.pauseUntil = q.clock().Add(wait)
			// An offline or air-gapped install would otherwise write this
			// line on every attempt for the life of the process.
			if q.apiFailures == 1 || q.apiFailures%20 == 0 {
				log.Printf("falcon telemetry: %v (%d attempts, %d events in this batch, next attempt in %s)", err, q.apiFailures, len(events), wait.Round(time.Second))
			}
			return 0
		}
		if q.apiFailures > 0 {
			log.Printf("falcon telemetry: reachable again after %d attempts", q.apiFailures)
			q.apiFailures = 0
		}
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
