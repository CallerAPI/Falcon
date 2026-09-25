package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/store"
)

const (
	pushBatch = 50
	pushBody  = 8 << 20
)

// Member copies local events to a hub and pulls the shared rules and the
// other nodes' caller counts. None of this runs on the INVITE path.
type Member struct {
	URL       string
	Token     string
	InstallID string
	Interval  time.Duration
	Store     store.Store
	Cache     *Cache
	Reload    func(context.Context) error
	HTTP      *http.Client
}

func (m *Member) Run(ctx context.Context) {
	if m.Interval <= 0 {
		m.Interval = 30 * time.Second
	}
	if m.HTTP == nil {
		m.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	m.Sync(ctx)
	t := time.NewTicker(m.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Sync(ctx)
		}
	}
}

// Sync pushes events and pulls rules and behaviour once.
func (m *Member) Sync(ctx context.Context) {
	if err := m.push(ctx); err != nil {
		log.Printf("falcon fleet push: %v", err)
	}
	if err := m.pullRules(ctx); err != nil {
		log.Printf("falcon fleet rules: %v", err)
	}
	if err := m.pullBehaviour(ctx); err != nil {
		log.Printf("falcon fleet behaviour: %v", err)
	}
}

func (m *Member) push(ctx context.Context) error {
	events, err := m.Store.FleetPending(ctx, pushBatch)
	if err != nil || len(events) == 0 {
		return err
	}
	body, err := json.Marshal(map[string]any{"install_id": m.InstallID, "events": events})
	if err != nil {
		return err
	}
	if err := m.post(ctx, "/v1/fleet/events", body); err != nil {
		return err
	}
	ids := make([]int64, len(events))
	for i, ev := range events {
		ids[i] = ev.ID
	}
	return m.Store.MarkFleetSent(ctx, ids)
}

func (m *Member) pullRules(ctx context.Context) error {
	var payload struct {
		Data []lists.Rule `json:"data"`
	}
	if err := m.get(ctx, "/v1/fleet/rules", &payload); err != nil {
		return err
	}
	if err := m.Store.ReplaceFleetRules(ctx, payload.Data); err != nil {
		return err
	}
	if m.Reload != nil {
		return m.Reload(ctx)
	}
	return nil
}

func (m *Member) pullBehaviour(ctx context.Context) error {
	var payload struct {
		Callers map[string]store.Activity `json:"callers"`
	}
	path := "/v1/fleet/behaviour?exclude=" + m.InstallID
	if err := m.get(ctx, path, &payload); err != nil {
		return err
	}
	if m.Cache != nil {
		m.Cache.Replace(payload.Callers)
	}
	return nil
}

func (m *Member) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (m *Member) post(ctx context.Context, path string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.URL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.Token)
	resp, err := m.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %s", path, resp.Status)
	}
	return nil
}

func (m *Member) get(ctx context.Context, path string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.URL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.Token)
	resp, err := m.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s returned %s", path, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, pushBody)).Decode(dest)
}
