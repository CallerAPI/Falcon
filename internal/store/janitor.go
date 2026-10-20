package store

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Retention is the set of windows the janitor enforces.
type Retention struct {
	// Events is how long a decision row lives.
	Events time.Duration
	// RawSIP is how long the raw message stays on a row before it is
	// blanked. Zero keeps it for the life of the row.
	RawSIP time.Duration
	// Recordings is how long a call recording stays on disk. The
	// transcript and the verdict stay with the row. Zero keeps them.
	Recordings time.Duration
	// RecordingsDir is the folder recording paths are relative to.
	RecordingsDir string
}

// Janitor prunes old events, scrubs raw SIP, and deletes old recordings
// once an hour. It reads the current retention each time, so a change in
// the dashboard takes effect without a restart.
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
		if r.Recordings > 0 && r.RecordingsDir != "" {
			if n := pruneRecordings(cctx, s, r); n > 0 {
				log.Printf("falcon janitor: deleted %d recordings older than %s", n, r.Recordings)
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

func pruneRecordings(ctx context.Context, s Store, r Retention) int {
	before := time.Now().Add(-r.Recordings)
	deleted := 0
	calls, err := s.ExpiredRecordings(ctx, before, 1000)
	if err != nil {
		log.Printf("falcon janitor: recordings: %v", err)
	}
	for _, m := range calls {
		if removeRecording(r.RecordingsDir, m.Recording) {
			deleted++
		}
		_ = s.ClearRecording(ctx, m.ID)
	}
	samples, err := s.ExpiredVoiceAudio(ctx, before, 1000)
	if err != nil {
		log.Printf("falcon janitor: voice audio: %v", err)
	}
	for _, v := range samples {
		if removeRecording(r.RecordingsDir, v.AudioPath) {
			deleted++
		}
		_ = s.ClearVoiceAudio(ctx, v.ID)
	}
	return deleted
}

// removeRecording deletes one file under dir. A path that leaves dir is
// refused.
func removeRecording(dir, rel string) bool {
	path, ok := RecordingPath(dir, rel)
	if !ok {
		return false
	}
	err := os.Remove(path)
	return err == nil || errors.Is(err, fs.ErrNotExist)
}

// RecordingPath joins a stored relative path onto the recordings folder.
// It refuses absolute paths and paths that climb out of the folder.
func RecordingPath(dir, rel string) (string, bool) {
	rel = strings.TrimSpace(rel)
	if dir == "" || rel == "" || filepath.IsAbs(rel) {
		return "", false
	}
	clean := filepath.Clean(rel)
	if clean == "." || strings.HasPrefix(clean, "..") {
		return "", false
	}
	return filepath.Join(dir, clean), true
}
