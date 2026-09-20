// Package reputation consumes the network feed CallerAPI builds from every
// sharing install: a score per signer SPC and per SIP fingerprint. It is the
// return leg of telemetry. The feed is fetched with the install's signed
// identity; CallerAPI serves it to installs that share.
package reputation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/callerapi/falcon/internal/identity"
)

// Path is the feed endpoint relative to the CallerAPI base.
const Path = "/api/falcon/v1/feed"

// Signer is the network view of one attesting provider.
type Signer struct {
	SPC      string `json:"spc"`
	Name     string `json:"name,omitempty"`
	Installs int    `json:"installs"`
	Calls    int    `json:"calls"`
	Verified int    `json:"verified"`
	Failed   int    `json:"failed"`
	Rejects  int    `json:"rejects"`
	SpamHits int    `json:"spam_hits"`
	Score    int    `json:"score"`
}

// Fingerprint is the network view of one sending tool.
type Fingerprint struct {
	Fingerprint string `json:"fingerprint"`
	UserAgent   string `json:"user_agent,omitempty"`
	Installs    int    `json:"installs"`
	Calls       int    `json:"calls"`
	Rejects     int    `json:"rejects"`
	SpamHits    int    `json:"spam_hits"`
	Score       int    `json:"score"`
}

// Feed is the wire format.
type Feed struct {
	GeneratedAt  time.Time     `json:"generated_at"`
	WindowDays   int           `json:"window_days"`
	Signers      []Signer      `json:"signers"`
	Fingerprints []Fingerprint `json:"fingerprints"`
}

// Table is the in-memory feed with refresh.
type Table struct {
	BaseURL string
	Key     *identity.Key
	HTTP    *http.Client
	Refresh time.Duration
	// Enabled reports whether the install is sharing right now. The feed is
	// only fetched while it is; CallerAPI enforces the same rule.
	Enabled func(context.Context) bool

	mu       sync.RWMutex
	signers  map[string]Signer
	prints   map[string]Fingerprint
	loadedAt time.Time
	genAt    time.Time
	err      string
}

// Status is what the dashboard shows.
type Status struct {
	Signers      int       `json:"signers"`
	Fingerprints int       `json:"fingerprints"`
	LoadedAt     time.Time `json:"loaded_at"`
	GeneratedAt  time.Time `json:"generated_at"`
	Error        string    `json:"error,omitempty"`
}

func (t *Table) Status() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return Status{Signers: len(t.signers), Fingerprints: len(t.prints), LoadedAt: t.loadedAt, GeneratedAt: t.genAt, Error: t.err}
}

// Signer returns the network view of an SPC.
func (t *Table) Signer(spc string) (Signer, bool) {
	if t == nil || spc == "" {
		return Signer{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	s, ok := t.signers[spc]
	return s, ok
}

// Fingerprint returns the network view of a tool.
func (t *Table) Fingerprint(fp string) (Fingerprint, bool) {
	if t == nil || fp == "" {
		return Fingerprint{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	f, ok := t.prints[fp]
	return f, ok
}

// Apply replaces the table. Exposed for tests and for a file-backed feed.
func (t *Table) Apply(f Feed) {
	signers := make(map[string]Signer, len(f.Signers))
	for _, s := range f.Signers {
		signers[s.SPC] = s
	}
	prints := make(map[string]Fingerprint, len(f.Fingerprints))
	for _, p := range f.Fingerprints {
		prints[p.Fingerprint] = p
	}
	t.mu.Lock()
	t.signers, t.prints = signers, prints
	t.loadedAt = time.Now().UTC()
	t.genAt = f.GeneratedAt
	t.err = ""
	t.mu.Unlock()
}

// Load fetches the feed once.
func (t *Table) Load(ctx context.Context) error {
	if t.BaseURL == "" || t.Key == nil {
		return errors.New("reputation: no base url or key")
	}
	if t.Enabled != nil && !t.Enabled(ctx) {
		t.setErr("not sharing telemetry; the network feed is for sharing installs")
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(t.BaseURL, "/")+Path, nil)
	if err != nil {
		return err
	}
	t.Key.Sign(req, nil)
	req.Header.Set("Accept", "application/json")
	client := t.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		t.setErr(err.Error())
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		slurp, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		err := fmt.Errorf("%s %s", resp.Status, strings.TrimSpace(string(slurp)))
		t.setErr(err.Error())
		return err
	}
	var f Feed
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&f); err != nil {
		t.setErr(err.Error())
		return err
	}
	t.Apply(f)
	return nil
}

// Run refreshes on a timer until ctx ends.
func (t *Table) Run(ctx context.Context) {
	if t.Refresh <= 0 {
		t.Refresh = time.Hour
	}
	if err := t.Load(ctx); err != nil {
		log.Printf("falcon reputation: %v", err)
	}
	tick := time.NewTicker(t.Refresh)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := t.Load(ctx); err != nil {
				log.Printf("falcon reputation: %v", err)
			}
		}
	}
}

func (t *Table) setErr(e string) {
	t.mu.Lock()
	t.err = e
	t.mu.Unlock()
}
