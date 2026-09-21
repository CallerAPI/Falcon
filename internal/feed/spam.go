package feed

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Spam is a local copy of the CallerAPI spam snapshot.
type Spam struct {
	BaseURL  string
	APIKey   string
	Refresh  time.Duration
	HTTP     *http.Client
	mu       sync.RWMutex
	numbers  map[string]struct{}
	loadedAt time.Time
	lastErr  string
}

func NewSpam(baseURL, apiKey string, refresh time.Duration) *Spam {
	if refresh <= 0 {
		refresh = time.Hour
	}
	return &Spam{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		Refresh: refresh,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
		numbers: make(map[string]struct{}),
	}
}

func (s *Spam) Enabled() bool {
	return s != nil && s.APIKey != ""
}

func (s *Spam) Contains(num string) bool {
	if s == nil {
		return false
	}
	n := normalize(num)
	if n == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.numbers[n]
	if !ok {
		_, ok = s.numbers[strings.TrimPrefix(n, "+")]
	}
	return ok
}

// LoadNumbers replaces the in-memory set. Used by the Zoom demo swap.
func (s *Spam) LoadNumbers(nums []string) {
	if s == nil {
		return
	}
	next := make(map[string]struct{}, len(nums)*2)
	for _, raw := range nums {
		n := normalize(raw)
		if n == "" {
			continue
		}
		next[n] = struct{}{}
		next[strings.TrimPrefix(n, "+")] = struct{}{}
	}
	s.mu.Lock()
	s.numbers = next
	s.loadedAt = time.Now().UTC()
	s.lastErr = ""
	s.mu.Unlock()
}

func (s *Spam) Status() (count int, loadedAt time.Time, lastErr string) {
	if s == nil {
		return 0, time.Time{}, ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.numbers), s.loadedAt, s.lastErr
}

func (s *Spam) Run(ctx context.Context) {
	if !s.Enabled() {
		return
	}
	s.sync(ctx)
	t := time.NewTicker(s.Refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sync(ctx)
		}
	}
}

func (s *Spam) sync(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.BaseURL+"/api/spam-reports/csv", nil)
	if err != nil {
		s.setErr(err.Error())
		return
	}
	req.Header.Set("X-Auth", s.APIKey)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		s.setErr(err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		slurp, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		s.setErr(resp.Status + " " + string(slurp))
		return
	}
	next := make(map[string]struct{}, 4096)
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			if strings.Contains(strings.ToLower(line), "phone") {
				continue
			}
		}
		n := normalize(strings.Trim(line, `"`))
		if n != "" {
			next[n] = struct{}{}
			next[strings.TrimPrefix(n, "+")] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		s.setErr(err.Error())
		return
	}
	s.mu.Lock()
	s.numbers = next
	s.loadedAt = time.Now().UTC()
	s.lastErr = ""
	s.mu.Unlock()
	log.Printf("falcon spam feed: loaded %d numbers", len(next)/2)
}

func (s *Spam) setErr(msg string) {
	s.mu.Lock()
	s.lastErr = msg
	s.mu.Unlock()
	log.Printf("falcon spam feed: %s", msg)
}

func normalize(num string) string {
	n := strings.TrimSpace(num)
	if n == "" {
		return ""
	}
	var b strings.Builder
	if strings.HasPrefix(n, "+") {
		b.WriteByte('+')
	}
	for _, r := range n {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" || out == "+" {
		return ""
	}
	if !strings.HasPrefix(out, "+") {
		out = "+" + out
	}
	return out
}

// Lookup is one live CallerAPI /api/lookup call.
type Lookup struct {
	IsSpam    bool    `json:"is_spam"`
	SpamScore float64 `json:"spam_score"`
}

// Live looks up one number against the CallerAPI voice-firewall path.
type Live struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

func (l *Live) Enabled() bool {
	return l != nil && l.APIKey != "" && l.BaseURL != ""
}

func (l *Live) Lookup(ctx context.Context, phone string) (Lookup, error) {
	var out Lookup
	if !l.Enabled() || phone == "" {
		return out, nil
	}
	phone = strings.TrimPrefix(normalize(phone), "+")
	if phone == "" {
		return out, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(l.BaseURL, "/")+"/api/lookup/"+phone, nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("X-Auth", l.APIKey)
	client := l.HTTP
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return out, nil
	}
	var wrap struct {
		Data Lookup `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrap); err != nil {
		return out, err
	}
	return wrap.Data, nil
}

// BCID is one live CallerAPI /api/bcid/v1/verify answer.
type BCID struct {
	Verdict  string        `json:"verdict"`
	Action   string        `json:"action"`
	Reason   string        `json:"reason"`
	Identity *BCIDIdentity `json:"identity"`
}

// BCIDIdentity is the name the switch may show.
type BCIDIdentity struct {
	Verified bool   `json:"verified"`
	Name     string `json:"name"`
	LogoID   string `json:"logo_id"`
	LogoURL  string `json:"logo_url"`
}

// Verify asks CallerAPI whether the calling number announced this call.
// The telco is not charged. Fail-open: a transport or HTTP error returns
// an empty verdict so the switch does not drop the call.
func (l *Live) Verify(ctx context.Context, from, to, assertion string) (BCID, error) {
	var out BCID
	if !l.Enabled() || from == "" || to == "" {
		return out, nil
	}
	body, err := json.Marshal(map[string]string{
		"from":      from,
		"to":        to,
		"assertion": assertion,
	})
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(l.BaseURL, "/")+"/api/bcid/v1/verify", strings.NewReader(string(body)))
	if err != nil {
		return out, err
	}
	req.Header.Set("X-Auth", l.APIKey)
	req.Header.Set("Content-Type", "application/json")
	client := l.HTTP
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return out, nil
	}
	var wrap struct {
		Data BCID `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrap); err != nil {
		return out, err
	}
	return wrap.Data, nil
}
