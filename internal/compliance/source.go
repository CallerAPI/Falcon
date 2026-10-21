package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/identity"
)

// Path is the list endpoint relative to the CallerAPI base.
const Path = "/api/falcon/v1/enforcement"

// maxListBytes bounds one decoded list. The full RMD is about 10,000 rows.
const maxListBytes = 64 << 20

// Fetcher returns the newest list. notModified means the list behind etag
// is still current.
type Fetcher interface {
	Fetch(ctx context.Context, etag string) (l List, newETag string, notModified bool, err error)
}

// Source fetches the list from CallerAPI with the install's signed
// identity. CallerAPI serves it to installs that share or carry a key.
// APIKey, when set, goes in X-Auth.
type Source struct {
	BaseURL string
	Key     *identity.Key
	APIKey  string
	HTTP    *http.Client
}

func (s *Source) Fetch(ctx context.Context, etag string) (List, string, bool, error) {
	if s.BaseURL == "" || s.Key == nil {
		return List{}, "", false, errors.New("no CallerAPI base or install key")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.BaseURL, "/")+Path, nil)
	if err != nil {
		return List{}, "", false, err
	}
	s.Key.Sign(req, nil)
	req.Header.Set("Accept", "application/json")
	if s.APIKey != "" {
		req.Header.Set("X-Auth", s.APIKey)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return List{}, "", false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return List{}, etag, true, nil
	case resp.StatusCode == http.StatusForbidden:
		return List{}, "", false, errors.New("CallerAPI serves the FCC list to installs that have shared telemetry for a day, or that carry a CallerAPI key")
	case resp.StatusCode >= 300:
		slurp, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return List{}, "", false, fmt.Errorf("%s %s", resp.Status, strings.TrimSpace(string(slurp)))
	}
	var l List
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxListBytes)).Decode(&l); err != nil {
		return List{}, "", false, err
	}
	return l, resp.Header.Get("ETag"), false, nil
}

// File reads the list from a JSON file in the same format, for an install
// with no outbound access.
type File struct{ Path string }

func (f File) Fetch(_ context.Context, etag string) (List, string, bool, error) {
	info, err := os.Stat(f.Path)
	if err != nil {
		return List{}, "", false, err
	}
	tag := fmt.Sprintf("file:%d:%d", info.ModTime().UnixNano(), info.Size())
	if tag == etag {
		return List{}, etag, true, nil
	}
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return List{}, "", false, err
	}
	var l List
	if err := json.Unmarshal(b, &l); err != nil {
		return List{}, "", false, fmt.Errorf("%s: %w", f.Path, err)
	}
	return l, tag, false, nil
}
