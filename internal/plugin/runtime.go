// Package plugin loads CallerAPI catalog entries and applies them.
// A new entry appears on the next refresh. Falcon does not need a new build
// for a plugin that uses the sdk field list.
package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/sdk"
)

// ErrNotFound means the catalog has no view for that slug.
var ErrNotFound = errors.New("plugin not found")

// Runtime is the in-memory catalog.
type Runtime struct {
	BaseURL string
	APIKey  string
	Refresh time.Duration
	Budget  time.Duration
	HTTP    *http.Client

	mu    sync.RWMutex
	items []sdk.Manifest
	feeds map[string]map[string]struct{}
}

func New(baseURL, apiKey string, refresh, budget time.Duration) *Runtime {
	if refresh <= 0 {
		refresh = time.Minute
	}
	if budget <= 0 {
		budget = 400 * time.Millisecond
	}
	return &Runtime{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		Refresh: refresh,
		Budget:  budget,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		feeds:   map[string]map[string]struct{}{},
	}
}

func (r *Runtime) Enabled() bool { return r != nil && r.APIKey != "" }

// Count is how many plugins the last refresh loaded.
func (r *Runtime) Count() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.items)
}

// Run refreshes until ctx ends. Failures keep the previous catalog.
func (r *Runtime) Run(ctx context.Context) {
	if !r.Enabled() {
		return
	}
	r.refresh(ctx)
	t := time.NewTicker(r.Refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.refresh(ctx)
		}
	}
}

// Load fetches the catalog once. Run calls it on a timer.
func (r *Runtime) Load(ctx context.Context) { r.refresh(ctx) }

func (r *Runtime) refresh(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.BaseURL+"/api/falcon/v1/plugins", nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Auth", r.APIKey)
	resp, err := r.HTTP.Do(req)
	if err != nil {
		log.Printf("falcon plugins: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("falcon plugins: catalog returned %s", resp.Status)
		return
	}
	var body struct {
		Plugins []sdk.Manifest `json:"plugins"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		log.Printf("falcon plugins: %v", err)
		return
	}
	feeds := map[string]map[string]struct{}{}
	for _, item := range body.Plugins {
		if item.Kind != "feed" {
			continue
		}
		keys, err := r.pullFeed(ctx, item.Slug)
		if err != nil {
			log.Printf("falcon plugins: feed %s: %v", item.Slug, err)
			continue
		}
		set := map[string]struct{}{}
		for _, k := range keys {
			set[k] = struct{}{}
		}
		feeds[item.Slug] = set
	}
	r.mu.Lock()
	r.items = body.Plugins
	r.feeds = feeds
	r.mu.Unlock()
}

func (r *Runtime) pullFeed(ctx context.Context, slug string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.BaseURL+"/api/falcon/v1/plugins/"+slug+"/feed", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth", r.APIKey)
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	var body struct {
		Keys []string `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&body); err != nil {
		return nil, err
	}
	return body.Keys, nil
}

// Apply runs every loaded plugin. Feed hits are local. Live checks share one
// budget and a failure leaves the decision unchanged.
func (r *Runtime) Apply(ctx context.Context, in sdk.Input, res score.Result, th score.Thresholds) score.Result {
	if r == nil {
		return res
	}
	r.mu.RLock()
	items := append([]sdk.Manifest(nil), r.items...)
	feeds := r.feeds
	r.mu.RUnlock()
	if len(items) == 0 {
		return res
	}
	liveCtx, cancel := context.WithTimeout(ctx, r.Budget)
	defer cancel()
	for _, item := range items {
		var out sdk.Output
		var ok bool
		switch item.Kind {
		case "view":
			continue
		case "feed":
			out, ok = feedHit(item, in, feeds[item.Slug])
		case "live":
			var err error
			out, err = r.evalLive(liveCtx, item, in)
			ok = err == nil
		default:
			continue
		}
		if !ok {
			continue
		}
		res = patch(res, item, out, th)
	}
	return res
}

func feedHit(item sdk.Manifest, in sdk.Input, keys map[string]struct{}) (sdk.Output, bool) {
	if len(keys) == 0 {
		return sdk.Output{}, false
	}
	key := in.From
	if item.KeyField == "source_ip" {
		key = in.SourceIP
	}
	if _, hit := keys[key]; !hit {
		return sdk.Output{}, false
	}
	return sdk.Output{Weight: 50, Reason: "plugin_" + item.Slug, Action: "flag"}, true
}

func (r *Runtime) evalLive(ctx context.Context, item sdk.Manifest, in sdk.Input) (sdk.Output, error) {
	payload, _ := json.Marshal(sdk.Select(in.AsMap(), item.Inputs))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.BaseURL+"/api/falcon/v1/plugins/"+item.Slug+"/eval", bytes.NewReader(payload))
	if err != nil {
		return sdk.Output{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth", r.APIKey)
	client := r.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return sdk.Output{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return sdk.Output{}, fmt.Errorf("status %s", resp.Status)
	}
	var out sdk.Output
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out); err != nil {
		return sdk.Output{}, err
	}
	return out, nil
}

func patch(res score.Result, item sdk.Manifest, out sdk.Output, th score.Thresholds) score.Result {
	if out.Weight < 0 {
		out.Weight = 0
	}
	if out.Weight > 100 {
		out.Weight = 100
	}
	reason := out.Reason
	if reason == "" {
		reason = "plugin_" + item.Slug
	}
	if out.Weight > 0 || out.Action != "" {
		res.Reasons = append(res.Reasons, score.Reason{
			Code: reason, Weight: out.Weight, Detail: trimDetail(out.Detail), Category: "plugin",
		})
	}
	res.RiskScore += out.Weight
	if res.RiskScore > 100 {
		res.RiskScore = 100
	}
	if res.Headers == nil {
		res.Headers = map[string]string{}
	}
	res.Headers["X-Falcon-Plugin"] = item.Slug
	mode := item.Mode
	if mode == "" {
		mode = "monitor"
	}
	want := score.Action(out.Action)
	if want == "" && out.Weight > 0 && res.Headers["X-Falcon-Block"] == "" {
		want = th.Action(res.RiskScore)
	}
	if mode == "monitor" && (want == score.ActionReject || want == score.ActionChallenge) {
		res.Headers["X-Falcon-Plugin-Monitor"] = string(want)
		if scoreRank(res.Action) < scoreRank(score.ActionFlag) {
			res.Action = score.ActionFlag
		}
		return syncDecision(res)
	}
	if scoreRank(want) > scoreRank(res.Action) {
		res.Action = want
		if want == score.ActionReject {
			res.Headers["X-Falcon-Block"] = "plugin"
		}
	}
	return syncDecision(res)
}

func syncDecision(res score.Result) score.Result {
	if res.Headers == nil {
		res.Headers = map[string]string{}
	}
	res.Headers["X-Falcon-Score"] = strconv.Itoa(res.RiskScore)
	res.Headers["X-Falcon-Action"] = string(res.Action)
	codes := make([]string, 0, len(res.Reasons))
	for _, reason := range res.Reasons {
		if reason.Code != "" {
			codes = append(codes, reason.Code)
		}
	}
	res.Headers["X-Falcon-Reasons"] = strings.Join(codes, ",")
	res.SIPStatus, res.SIPReason = res.Action.SIP()
	return res
}

func scoreRank(a score.Action) int {
	switch a {
	case score.ActionFlag:
		return 1
	case score.ActionChallenge:
		return 2
	case score.ActionReject:
		return 3
	default:
		return 0
	}
}

func trimDetail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// List is the catalog the dashboard may show.
func (r *Runtime) List() []sdk.Manifest {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]sdk.Manifest(nil), r.items...)
}

// Panel loads one plugin view. The query is the operator search. Screening
// fields are not sent. An iframe URL on another host is refused.
func (r *Runtime) Panel(ctx context.Context, slug, query string) (sdk.Panel, error) {
	if r == nil {
		return sdk.Panel{}, fmt.Errorf("plugins off")
	}
	slug = strings.TrimSpace(slug)
	var item sdk.Manifest
	found := false
	for _, it := range r.List() {
		if it.Slug == slug {
			item = it
			found = true
			break
		}
	}
	if !found || (item.Surface != "native" && item.Surface != "iframe") {
		return sdk.Panel{}, ErrNotFound
	}
	q := url.Values{}
	q.Set("q", sdk.CleanQuery(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.BaseURL+"/api/falcon/v1/plugins/"+url.PathEscape(slug)+"/view?"+q.Encode(), nil)
	if err != nil {
		return sdk.Panel{}, err
	}
	req.Header.Set("X-Auth", r.APIKey)
	client := r.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return sdk.Panel{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return sdk.Panel{}, fmt.Errorf("status %s", resp.Status)
	}
	var panel sdk.Panel
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&panel); err != nil {
		return sdk.Panel{}, err
	}
	panel = sdk.SanitizePanel(panel)
	panel.Surface = item.Surface
	if item.Title != "" {
		panel.Title = item.Title
	}
	if item.Surface == "iframe" {
		if panel.FrameURL != "" && !sdk.SameOrigin(r.BaseURL, panel.FrameURL) {
			return sdk.Panel{}, fmt.Errorf("frame host refused")
		}
		panel.FrameURL = ""
		panel.FrameOrigin = ""
		panel.Columns = nil
		panel.Rows = nil
		panel.Stats = nil
	}
	return panel, nil
}

// Import sends a file to CallerAPI and returns the inventory panel.
// The browser does not call CallerAPI. The file stays on this request.
func (r *Runtime) Import(ctx context.Context, slug string, body []byte) (sdk.Panel, error) {
	if r == nil {
		return sdk.Panel{}, fmt.Errorf("plugins off")
	}
	found := false
	for _, it := range r.List() {
		if it.Slug == slug && it.Surface == "native" {
			found = true
			break
		}
	}
	if !found {
		return sdk.Panel{}, ErrNotFound
	}
	buf := &bytes.Buffer{}
	contentType, err := buildImportForm(buf, body)
	if err != nil {
		return sdk.Panel{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.BaseURL+"/api/falcon/v1/plugins/"+url.PathEscape(slug)+"/import", buf)
	if err != nil {
		return sdk.Panel{}, err
	}
	req.Header.Set("X-Auth", r.APIKey)
	req.Header.Set("Content-Type", contentType)
	client := r.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	cloned := *client
	if cloned.Timeout < time.Minute {
		cloned.Timeout = 2 * time.Minute
	}
	resp, err := cloned.Do(req)
	if err != nil {
		return sdk.Panel{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return sdk.Panel{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		var payload map[string]string
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&payload)
		msg := payload["message"]
		if msg == "" {
			msg = payload["error"]
		}
		if msg == "" {
			msg = resp.Status
		}
		return sdk.Panel{}, errors.New(msg)
	}
	var panel sdk.Panel
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&panel); err != nil {
		return sdk.Panel{}, err
	}
	panel = sdk.SanitizePanel(panel)
	panel.Surface = "native"
	return panel, nil
}

var buildImportForm = writeImportForm

// Schedule reads the recheck schedule for one native plugin.
func (r *Runtime) Schedule(ctx context.Context, slug string) ([]byte, error) {
	return r.pluginCall(ctx, http.MethodGet, slug, "schedule", nil)
}

// SaveSchedule stores the recheck schedule. The browser does not call CallerAPI.
func (r *Runtime) SaveSchedule(ctx context.Context, slug string, body []byte) ([]byte, error) {
	return r.pluginCall(ctx, http.MethodPut, slug, "schedule", body)
}

func (r *Runtime) pluginCall(ctx context.Context, method, slug, kind string, body []byte) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("plugins off")
	}
	found := false
	for _, it := range r.List() {
		if it.Slug == slug && it.Surface == "native" {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrNotFound
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.BaseURL+"/api/falcon/v1/plugins/"+url.PathEscape(slug)+"/"+kind, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth", r.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := r.HTTP
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
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		var payload map[string]string
		_ = json.Unmarshal(raw, &payload)
		msg := payload["message"]
		if msg == "" {
			msg = payload["error"]
		}
		if msg == "" {
			msg = resp.Status
		}
		return nil, errors.New(msg)
	}
	return raw, nil
}

func writeImportForm(dst io.Writer, body []byte) (string, error) {
	w := multipart.NewWriter(dst)
	part, err := w.CreateFormFile("file", "numbers")
	if err != nil {
		return "", err
	}
	if _, err := part.Write(body); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return w.FormDataContentType(), nil
}

// Page fetches the plugin HTML. Falcon serves it on its own host. The
// browser does not call CallerAPI.
func (r *Runtime) Page(ctx context.Context, slug, query string) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("plugins off")
	}
	found := false
	for _, it := range r.List() {
		if it.Slug == slug && it.Surface == "iframe" {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrNotFound
	}
	q := url.Values{}
	q.Set("q", sdk.CleanQuery(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.BaseURL+"/api/falcon/v1/plugins/"+url.PathEscape(slug)+"/frame?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth", r.APIKey)
	client := r.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil, err
	}
	if strings.Contains(strings.ToLower(string(body)), "<script") {
		return nil, fmt.Errorf("script refused")
	}
	return body, nil
}

// View builds the sdk input from a scored call. The called number is absent.
func View(from, sourceIP, ua, callID, attest, verstat, spc, signer, provider, fingerprint, direction, method string, scoreValue int, action string, reasons []score.Reason) sdk.Input {
	codes := make([]string, 0, len(reasons))
	for _, r := range reasons {
		if r.Code != "" {
			codes = append(codes, r.Code)
		}
	}
	return sdk.Input{
		From: from, SourceIP: sourceIP, UserAgent: ua, CallID: callID, Attest: attest,
		Verstat: verstat, SignerSPC: spc, SignerName: signer, Provider: provider,
		Fingerprint: fingerprint, Direction: direction, Method: method,
		Action: action, Score: strconv.Itoa(scoreValue), ReasonCodes: strings.Join(codes, ","),
	}
}
