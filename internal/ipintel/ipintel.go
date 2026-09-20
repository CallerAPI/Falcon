// Package ipintel maps a source IP onto the telecom provider that announces
// it and the risk that provider carries. The table is a CSV of CIDR blocks.
// It loads from a local file, a URL, or both, and refreshes on a timer, so a
// laptop and a fleet read the same format from wherever they keep it.
package ipintel

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// Risk is the provider's standing on the list.
type Risk string

const (
	// RiskTrusted is a carrier the operator peers with on purpose.
	RiskTrusted Risk = "trusted"
	// RiskNeutral names the provider and says nothing about risk.
	RiskNeutral Risk = "neutral"
	// RiskSuspicious is a provider with a history but no verdict.
	RiskSuspicious Risk = "suspicious"
	// RiskHostile is a provider the operator wants weighted toward reject.
	RiskHostile Risk = "hostile"
	// RiskBlock is a hard reject for any request from the block.
	RiskBlock Risk = "block"
)

// Entry is one CIDR row.
type Entry struct {
	Prefix   netip.Prefix `json:"cidr"`
	Provider string       `json:"provider"`
	Risk     Risk         `json:"risk"`
	Tags     []string     `json:"tags,omitempty"`
	Source   string       `json:"source,omitempty"`
}

// Match is a lookup hit.
type Match struct {
	Entry
	IP netip.Addr `json:"ip"`
}

// Table holds the CIDR rows and answers lookups. Rows are keyed by prefix
// length, so a lookup masks the address at each length from long to short
// and does at most 32 or 128 map reads. Longest prefix wins.
type Table struct {
	mu       sync.RWMutex
	v4       map[int]map[netip.Prefix]Entry
	v6       map[int]map[netip.Prefix]Entry
	count    int
	loadedAt time.Time
	lastErr  string

	// FilePath and URL are the sources. Either may be empty. When both are
	// set the file is read second, so a local row overrides a hosted one.
	FilePath string
	URL      string
	APIKey   string
	Refresh  time.Duration
	HTTP     *http.Client
}

// New returns an empty table with the given sources.
func New(filePath, url, apiKey string, refresh time.Duration) *Table {
	if refresh <= 0 {
		refresh = time.Hour
	}
	return &Table{
		v4:       map[int]map[netip.Prefix]Entry{},
		v6:       map[int]map[netip.Prefix]Entry{},
		FilePath: strings.TrimSpace(filePath),
		URL:      strings.TrimSpace(url),
		APIKey:   apiKey,
		Refresh:  refresh,
		HTTP:     &http.Client{Timeout: 60 * time.Second},
	}
}

// Enabled reports whether any source is configured.
func (t *Table) Enabled() bool {
	return t != nil && (t.FilePath != "" || t.URL != "")
}

// Lookup returns the longest matching row for ip.
func (t *Table) Lookup(ip string) (Match, bool) {
	if t == nil {
		return Match{}, false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return Match{}, false
	}
	addr = addr.Unmap()
	t.mu.RLock()
	defer t.mu.RUnlock()
	byLen := t.v4
	maxBits := 32
	if addr.Is6() {
		byLen = t.v6
		maxBits = 128
	}
	for bits := maxBits; bits >= 0; bits-- {
		rows := byLen[bits]
		if len(rows) == 0 {
			continue
		}
		p, err := addr.Prefix(bits)
		if err != nil {
			continue
		}
		if e, ok := rows[p]; ok {
			return Match{Entry: e, IP: addr}, true
		}
	}
	return Match{}, false
}

// Status reports row count, last load time and last error.
func (t *Table) Status() (count int, loadedAt time.Time, lastErr string) {
	if t == nil {
		return 0, time.Time{}, ""
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.count, t.loadedAt, t.lastErr
}

// Run loads the table, then reloads every Refresh until ctx ends.
func (t *Table) Run(ctx context.Context) {
	if !t.Enabled() {
		return
	}
	t.Load(ctx)
	tick := time.NewTicker(t.Refresh)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t.Load(ctx)
		}
	}
}

// Load reads every configured source and swaps the table in one step. A
// source that fails leaves the previous table in place and records the error.
func (t *Table) Load(ctx context.Context) {
	next := newIndex()
	var errs []string
	loaded := 0
	if t.URL != "" {
		n, err := t.loadURL(ctx, next)
		if err != nil {
			errs = append(errs, "url: "+err.Error())
		}
		loaded += n
	}
	if t.FilePath != "" {
		n, err := t.loadFile(next)
		if err != nil {
			errs = append(errs, "file: "+err.Error())
		}
		loaded += n
	}
	if loaded == 0 && len(errs) > 0 {
		t.setErr(strings.Join(errs, "; "))
		return
	}
	t.mu.Lock()
	t.v4, t.v6 = next.v4, next.v6
	t.count = next.count
	t.loadedAt = time.Now().UTC()
	t.lastErr = strings.Join(errs, "; ")
	t.mu.Unlock()
	log.Printf("falcon ip intel: loaded %d blocks", next.count)
}

func (t *Table) loadFile(idx *index) (int, error) {
	f, err := os.Open(t.FilePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return Parse(f, idx)
}

func (t *Table) loadURL(ctx context.Context, idx *index) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	if err != nil {
		return 0, err
	}
	if t.APIKey != "" {
		req.Header.Set("X-Auth", t.APIKey)
	}
	client := t.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		slurp, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return 0, fmt.Errorf("%s %s", resp.Status, strings.TrimSpace(string(slurp)))
	}
	return Parse(resp.Body, idx)
}

func (t *Table) setErr(msg string) {
	t.mu.Lock()
	t.lastErr = msg
	t.mu.Unlock()
	log.Printf("falcon ip intel: %s", msg)
}

type index struct {
	v4    map[int]map[netip.Prefix]Entry
	v6    map[int]map[netip.Prefix]Entry
	count int
}

func newIndex() *index {
	return &index{v4: map[int]map[netip.Prefix]Entry{}, v6: map[int]map[netip.Prefix]Entry{}}
}

func (i *index) add(e Entry) {
	byLen := i.v4
	if e.Prefix.Addr().Is6() {
		byLen = i.v6
	}
	rows := byLen[e.Prefix.Bits()]
	if rows == nil {
		rows = map[netip.Prefix]Entry{}
		byLen[e.Prefix.Bits()] = rows
	}
	if _, exists := rows[e.Prefix]; !exists {
		i.count++
	}
	rows[e.Prefix] = e
}

// Parse reads CSV rows of the form
//
//	cidr,provider,risk,tags,source
//
// into idx. A header row is skipped. Tags are separated by "|" or ";". A bare
// IP is a /32 or /128. Blank lines and lines starting with "#" are ignored.
// Rows that do not parse are counted as errors but do not stop the load.
func Parse(r io.Reader, idx *index) (int, error) {
	br := bufio.NewReader(r)
	cr := csv.NewReader(br)
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	cr.Comment = '#'
	added, bad := 0, 0
	first := true
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			bad++
			continue
		}
		if len(rec) == 0 || strings.TrimSpace(rec[0]) == "" {
			continue
		}
		if first {
			first = false
			if strings.EqualFold(strings.TrimSpace(rec[0]), "cidr") {
				continue
			}
		}
		e, err := entryFromRecord(rec)
		if err != nil {
			bad++
			continue
		}
		idx.add(e)
		added++
	}
	if bad > 0 {
		return added, fmt.Errorf("%d rows skipped", bad)
	}
	return added, nil
}

func entryFromRecord(rec []string) (Entry, error) {
	raw := strings.TrimSpace(rec[0])
	var p netip.Prefix
	if strings.Contains(raw, "/") {
		parsed, err := netip.ParsePrefix(raw)
		if err != nil {
			return Entry{}, err
		}
		p = parsed.Masked()
	} else {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return Entry{}, err
		}
		addr = addr.Unmap()
		p = netip.PrefixFrom(addr, addr.BitLen())
	}
	e := Entry{Prefix: p, Risk: RiskNeutral}
	if len(rec) > 1 {
		e.Provider = strings.TrimSpace(rec[1])
	}
	if len(rec) > 2 {
		e.Risk = ParseRisk(rec[2])
	}
	if len(rec) > 3 {
		e.Tags = splitTags(rec[3])
	}
	if len(rec) > 4 {
		e.Source = strings.TrimSpace(rec[4])
	}
	return e, nil
}

// ParseRisk maps a column value onto a Risk. Unknown values are neutral.
func ParseRisk(s string) Risk {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trusted", "trust", "allow", "whitelist":
		return RiskTrusted
	case "suspicious", "suspect", "gray", "grey", "watch":
		return RiskSuspicious
	case "hostile", "bad", "high", "abuse", "scanner":
		return RiskHostile
	case "block", "reject", "deny", "blacklist":
		return RiskBlock
	default:
		return RiskNeutral
	}
}

func splitTags(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '|' || r == ';' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
