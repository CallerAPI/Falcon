package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/identity"
	"github.com/callerapi/falcon/internal/share"
	"github.com/callerapi/falcon/internal/store"
)

// CallerAPI sends redacted screening events to api.callerapi.com. Every
// event passes through share.Redact first: the called party, forwarding
// numbers, the PASSporT, and the SDP body never leave the host. An API key
// is optional; with one, the account is credited for the contribution.
type CallerAPI struct {
	BaseURL   string
	APIKey    string
	InstallID string
	Version   string
	// HMACKey is the per-install secret behind to_hmac.
	HMACKey []byte
	// Key signs every post so CallerAPI can bind the install id to a key.
	Key  *identity.Key
	HTTP *http.Client
}

type telemetryRequest struct {
	InstallID string         `json:"install_id"`
	Version   string         `json:"version"`
	Events    []share.Event  `json:"events"`
	Rollups   []share.Rollup `json:"rollups,omitempty"`
}

// Batch is one telemetry post. Kinds runs parallel to Events.
type Batch struct {
	Events  []store.Event
	Kinds   []string
	Rollups []share.Rollup
}

func (c *CallerAPI) Enabled() bool {
	return c != nil && c.BaseURL != ""
}

// Endpoint is the telemetry path relative to BaseURL.
const Endpoint = "/api/falcon/v1/telemetry"

// Send redacts the events and posts them with the rollups.
func (c *CallerAPI) Send(ctx context.Context, b Batch) error {
	if !c.Enabled() || (len(b.Events) == 0 && len(b.Rollups) == 0) {
		return nil
	}
	payload := telemetryRequest{InstallID: c.InstallID, Version: c.Version, Events: []share.Event{}, Rollups: b.Rollups}
	for i, ev := range b.Events {
		out := share.Redact(ev, c.HMACKey)
		if i < len(b.Kinds) {
			out.Kind = b.Kinds[i]
		}
		payload.Events = append(payload.Events, out)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "falcon/"+c.Version)
	if c.Key != nil {
		c.Key.Sign(req, body)
	}
	if c.APIKey != "" {
		req.Header.Set("X-Auth", c.APIKey)
	}

	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		slurp, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return &HTTPError{
			Status:     resp.Status,
			RetryAfter: retryAfter(resp.Header.Get("Retry-After"), time.Now()),
			Body:       string(slurp),
		}
	}
	return nil
}

// HTTPError is a telemetry post that CallerAPI did not accept. RetryAfter is
// zero when the answer had no Retry-After header.
type HTTPError struct {
	Status     string
	RetryAfter time.Duration
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("callerapi telemetry: %s %s", e.Status, e.Body)
}

// retryAfter reads a Retry-After value in seconds or as an HTTP date.
func retryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil {
		return max(time.Duration(s)*time.Second, 0)
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0)
	}
	return 0
}
