package export

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
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
}

func (q *Queue) Run(ctx context.Context) {
	if q.Interval <= 0 {
		q.Interval = 30 * time.Second
	}
	t := time.NewTicker(q.Interval)
	defer t.Stop()
	q.flush(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			q.flush(ctx)
		}
	}
}

func (q *Queue) flush(ctx context.Context) {
	wantS3 := q.S3 != nil && q.S3.Enabled()
	wantAPI := q.CallerAPI != nil && q.CallerAPI.Enabled() && (q.CallerAPIReady == nil || q.CallerAPIReady(ctx))
	if !wantS3 && !wantAPI {
		return
	}
	events, err := q.Store.Unexported(ctx, 100)
	if err != nil || len(events) == 0 {
		return
	}

	if wantS3 {
		if err := q.putS3(ctx, events); err != nil {
			log.Printf("falcon export s3: %v", err)
			return
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
			// An offline or air-gapped install would otherwise write this
			// line every 30 seconds for the life of the process.
			q.apiFailures++
			if q.apiFailures == 1 || q.apiFailures%120 == 0 {
				log.Printf("falcon telemetry: %v (%d attempts, %d events waiting, retrying every %s)", err, q.apiFailures, len(events), q.Interval)
			}
			return
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
	}
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
