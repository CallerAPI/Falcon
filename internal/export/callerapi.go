package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	InstallID string        `json:"install_id"`
	Version   string        `json:"version"`
	Events    []share.Event `json:"events"`
}

func (c *CallerAPI) Enabled() bool {
	return c != nil && c.BaseURL != ""
}

// Endpoint is the telemetry path relative to BaseURL.
const Endpoint = "/api/falcon/v1/telemetry"

func (c *CallerAPI) Ingest(ctx context.Context, events []store.Event) error {
	if !c.Enabled() || len(events) == 0 {
		return nil
	}
	payload := telemetryRequest{InstallID: c.InstallID, Version: c.Version}
	for _, ev := range events {
		payload.Events = append(payload.Events, share.Redact(ev, c.HMACKey))
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
		return fmt.Errorf("callerapi telemetry: %s %s", resp.Status, string(slurp))
	}
	return nil
}
