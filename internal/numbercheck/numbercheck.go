// Package numbercheck keeps the operator's own numbers on CallerAPI and
// rechecks their reputation. It is built in: the paths are fixed and the
// account key is the only credential. The browser never calls CallerAPI.
package numbercheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// ErrOff means no CallerAPI key is set.
var ErrOff = errors.New("number check needs CALLERAPI_API_KEY")

const basePath = "/api/falcon/v1/plugins/number-check/"

// Column is one table column.
type Column struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// Stat is one summary figure.
type Stat struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Panel is the saved list and its summary.
type Panel struct {
	Columns []Column            `json:"columns"`
	Rows    []map[string]string `json:"rows"`
	Stats   []Stat              `json:"stats"`
}

// Client calls the CallerAPI number check endpoints.
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// New returns nil when there is no key, so callers can test for nil.
func New(baseURL, apiKey string) *Client {
	if strings.TrimSpace(apiKey) == "" {
		return nil
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), APIKey: apiKey, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// View returns the saved numbers. query filters by number.
func (c *Client) View(ctx context.Context, query string) (Panel, error) {
	q := url.Values{}
	q.Set("q", cleanQuery(query))
	raw, err := c.call(ctx, http.MethodGet, "view?"+q.Encode(), "", nil, 30*time.Second)
	if err != nil {
		return Panel{}, err
	}
	return decodePanel(raw)
}

// Import sends a file. CallerAPI finds the numbers in it. Each new number
// costs 1 credit.
func (c *Client) Import(ctx context.Context, file []byte) (Panel, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", "numbers")
	if err != nil {
		return Panel{}, err
	}
	if _, err := part.Write(file); err != nil {
		return Panel{}, err
	}
	if err := w.Close(); err != nil {
		return Panel{}, err
	}
	raw, err := c.call(ctx, http.MethodPost, "import", w.FormDataContentType(), &buf, 2*time.Minute)
	if err != nil {
		return Panel{}, err
	}
	return decodePanel(raw)
}

// Schedule reads the recheck schedule as JSON.
func (c *Client) Schedule(ctx context.Context) ([]byte, error) {
	return c.call(ctx, http.MethodGet, "schedule", "", nil, 30*time.Second)
}

// SaveSchedule stores the recheck schedule. Each recheck costs 1 credit
// per number.
func (c *Client) SaveSchedule(ctx context.Context, body []byte) ([]byte, error) {
	if !json.Valid(body) {
		return nil, errors.New("schedule must be JSON")
	}
	return c.call(ctx, http.MethodPut, "schedule", "application/json", bytes.NewReader(body), 30*time.Second)
}

func (c *Client) call(ctx context.Context, method, path, contentType string, body io.Reader, timeout time.Duration) ([]byte, error) {
	if c == nil {
		return nil, ErrOff
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+basePath+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth", c.APIKey)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var payload map[string]any
		_ = json.Unmarshal(raw, &payload)
		for _, key := range []string{"message", "error"} {
			if msg, ok := payload[key].(string); ok && msg != "" {
				return nil, errors.New(msg)
			}
		}
		return nil, fmt.Errorf("number check: %s", resp.Status)
	}
	return raw, nil
}

func decodePanel(raw []byte) (Panel, error) {
	var in Panel
	if err := json.Unmarshal(raw, &in); err != nil {
		return Panel{}, err
	}
	out := Panel{Columns: []Column{}, Rows: []map[string]string{}, Stats: []Stat{}}
	for _, col := range in.Columns {
		if key := columnKey(col.Key); key != "" && len(out.Columns) < 8 {
			out.Columns = append(out.Columns, Column{Key: key, Label: clip(col.Label, 40)})
		}
	}
	for _, row := range in.Rows {
		if len(out.Rows) >= 200 {
			break
		}
		clean := map[string]string{}
		for _, col := range out.Columns {
			clean[col.Key] = clip(row[col.Key], 80)
		}
		out.Rows = append(out.Rows, clean)
	}
	for _, st := range in.Stats {
		if len(out.Stats) < 8 {
			out.Stats = append(out.Stats, Stat{Label: clip(st.Label, 40), Value: clip(st.Value, 40)})
		}
	}
	return out, nil
}

func cleanQuery(q string) string {
	q = strings.TrimSpace(q)
	if strings.ContainsAny(q, "<>\r\n") {
		return ""
	}
	return clip(q, 64)
}

func columnKey(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 32 {
		return ""
	}
	for _, r := range s {
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return ""
		}
	}
	return s
}

func clip(s string, n int) string {
	s = strings.TrimSpace(strings.NewReplacer("\n", " ", "\r", " ").Replace(s))
	if len(s) > n {
		s = s[:n]
	}
	return s
}
