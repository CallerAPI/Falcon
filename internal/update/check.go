// Package update reports when a newer Falcon release is public.
// It does not download or install that release.
package update

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/alerts"
	"github.com/callerapi/falcon/internal/safehttp"
	"github.com/callerapi/falcon/internal/store"
)

const releaseURL = "https://api.github.com/repos/CallerAPI/Falcon/releases/latest"

// Status is the last comparison. Current is this process.
type Status struct {
	Current string `json:"current"`
	Latest  string `json:"latest,omitempty"`
	URL     string `json:"url,omitempty"`
	Newer   bool   `json:"newer"`
}

// Checker polls the public release and pages once per new tag.
type Checker struct {
	Version  string
	Interval time.Duration
	Alerts   *alerts.Watcher
	Store    store.Store
	HTTP     *http.Client
	OnStatus func(Status)
	// URL overrides the public release endpoint. Tests set it. Empty uses GitHub.
	URL string
}

func (c *Checker) Run(ctx context.Context) {
	if c.Version == "" || c.Version == "dev" {
		return
	}
	if c.Interval <= 0 {
		c.Interval = 6 * time.Hour
	}
	if c.HTTP == nil {
		c.HTTP = safehttp.DefaultPolicy().Client()
	}
	c.once(ctx)
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.once(ctx)
		}
	}
}

func (c *Checker) once(ctx context.Context) {
	st, err := c.lookup(ctx)
	if err != nil {
		log.Printf("falcon update: %v", err)
		return
	}
	if c.OnStatus != nil {
		c.OnStatus(st)
	}
	if !st.Newer || c.Alerts == nil || c.Store == nil {
		return
	}
	prev, err := c.Store.KVGet(ctx, "update_notified")
	if err != nil || prev == st.Latest {
		return
	}
	c.Alerts.FireNow(ctx, alerts.Fired{
		Key: "release:" + st.Latest, Severity: "warning",
		Title:  "Falcon " + st.Latest + " is available",
		Detail: "This process runs " + st.Current + ". The public release is " + st.Latest + ". Falcon does not install it. Pin the new image when you are ready.",
		Data: map[string]any{
			"kind": "release", "current": st.Current, "latest": st.Latest, "url": st.URL,
			"suggested_action": "review_and_pin",
		},
	})
	_ = c.Store.KVSet(ctx, "update_notified", st.Latest)
}

func (c *Checker) lookup(ctx context.Context) (Status, error) {
	st := Status{Current: c.Version}
	endpoint := c.URL
	if endpoint == "" {
		endpoint = releaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return st, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "falcon/"+c.Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
		return st, errStatus(resp.StatusCode)
	}
	var payload struct {
		Tag string `json:"tag_name"`
		URL string `json:"html_url"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return st, err
	}
	st.Latest = strings.TrimPrefix(strings.TrimSpace(payload.Tag), "v")
	st.URL = payload.URL
	st.Newer = Newer(c.Version, st.Latest)
	return st, nil
}

type statusError string

func errStatus(code int) error { return statusError(http.StatusText(code)) }

func (e statusError) Error() string { return "release check returned " + string(e) }

// Newer reports whether latest is a higher dotted version than current.
// A dev build is never newer. Non-numeric parts are ignored.
func Newer(current, latest string) bool {
	current = strings.TrimPrefix(strings.TrimSpace(current), "v")
	latest = strings.TrimPrefix(strings.TrimSpace(latest), "v")
	if current == "" || current == "dev" || latest == "" || latest == current {
		return false
	}
	c, l := parts(current), parts(latest)
	n := len(c)
	if len(l) > n {
		n = len(l)
	}
	for i := 0; i < n; i++ {
		cv, lv := 0, 0
		if i < len(c) {
			cv = c[i]
		}
		if i < len(l) {
			lv = l[i]
		}
		if lv > cv {
			return true
		}
		if lv < cv {
			return false
		}
	}
	return false
}

func parts(v string) []int {
	fields := strings.Split(v, ".")
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil {
			return out
		}
		out = append(out, n)
	}
	return out
}
