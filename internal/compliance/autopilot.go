package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/callerapi/falcon/internal/alerts"
	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/store"
)

// Modes. Monitor records and alerts. Enforce also adds deny rules for every
// upstream with a confirmed bad standing.
const (
	ModeMonitor = "monitor"
	ModeEnforce = "enforce"

	// RuleOrigin marks the deny rules the autopilot owns. It replaces them
	// on every pass and never touches other rules.
	RuleOrigin = "fcc"

	kvList    = "fcc_list"
	kvETag    = "fcc_list_etag"
	kvBlocked = "fcc_blocked"
)

// Log actions.
const (
	ActionStanding = "standing"
	ActionBlocked  = "blocked"
	ActionReleased = "released"
)

// Store is what the autopilot reads and writes.
type Store interface {
	Upstreams(ctx context.Context) ([]store.Upstream, error)
	SetUpstreamStanding(ctx context.Context, id int64, standing string, since time.Time) error
	ReplaceOriginRules(ctx context.Context, origin string, rules []lists.Rule) error
	AddComplianceEntry(ctx context.Context, e store.ComplianceEntry) (int64, error)
	KVGet(ctx context.Context, key string) (string, error)
	KVSet(ctx context.Context, key, value string) error
}

// Autopilot keeps the list fresh and acts on it.
type Autopilot struct {
	Store  Store
	Source Fetcher
	// SourceName is shown in Settings: callerapi or file.
	SourceName string
	Mode       func(context.Context) string
	// Reload rebuilds the rule index after the rules change.
	Reload  func(context.Context) error
	Alert   func(context.Context, alerts.Fired)
	Refresh time.Duration
	Now     func() time.Time

	// run serializes passes. state guards what the API reads.
	run      sync.Mutex
	state    sync.RWMutex
	index    *Index
	results  map[int64]Result
	owners   *UpstreamIndex
	loadedAt time.Time
	checked  time.Time
	err      string
}

// Status is what Settings and the API show.
type Status struct {
	Source      string    `json:"source"`
	Providers   int       `json:"providers"`
	GeneratedAt time.Time `json:"generated_at"`
	LoadedAt    time.Time `json:"loaded_at"`
	CheckedAt   time.Time `json:"checked_at"`
	Error       string    `json:"error,omitempty"`
}

// Run loads the saved list, fetches a fresh one, and repeats on Refresh.
func (a *Autopilot) Run(ctx context.Context) {
	if a.Refresh <= 0 {
		a.Refresh = 6 * time.Hour
	}
	a.loadSaved(ctx)
	a.Sync(ctx)
	t := time.NewTicker(a.Refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.Sync(ctx)
		}
	}
}

// Sync fetches the list and evaluates every upstream. A failed fetch keeps
// the last good list.
func (a *Autopilot) Sync(ctx context.Context) {
	if err := a.fetch(ctx); err != nil {
		log.Printf("falcon fcc: %v", err)
	}
	if err := a.Evaluate(ctx); err != nil {
		log.Printf("falcon fcc: evaluate: %v", err)
	}
}

func (a *Autopilot) fetch(ctx context.Context) error {
	if a.Source == nil {
		return nil
	}
	etag, _ := a.Store.KVGet(ctx, kvETag)
	if a.currentIndex() == nil {
		etag = ""
	}
	l, newTag, notModified, err := a.Source.Fetch(ctx, etag)
	a.state.Lock()
	defer a.state.Unlock()
	if err != nil {
		a.err = err.Error()
		return err
	}
	a.err = ""
	a.loadedAt = a.now()
	if notModified {
		return nil
	}
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if err := a.Store.KVSet(ctx, kvList, string(b)); err != nil {
		return err
	}
	_ = a.Store.KVSet(ctx, kvETag, newTag)
	a.index = NewIndex(l)
	return nil
}

func (a *Autopilot) loadSaved(ctx context.Context) {
	raw, err := a.Store.KVGet(ctx, kvList)
	if err != nil || raw == "" {
		return
	}
	var l List
	if err := json.Unmarshal([]byte(raw), &l); err != nil {
		log.Printf("falcon fcc: saved list: %v", err)
		return
	}
	a.state.Lock()
	a.index = NewIndex(l)
	a.state.Unlock()
}

// Apply installs a list without a fetch. For tests and the demo.
func (a *Autopilot) Apply(l List) {
	a.state.Lock()
	a.index = NewIndex(l)
	a.loadedAt = a.now()
	a.err = ""
	a.state.Unlock()
}

// Evaluate checks every upstream, logs each change of standing, and in
// enforce mode replaces the autopilot's deny rules. Monitor mode removes
// them. Without a list the rules stay as they are, so a fetch failure never
// lifts a block.
func (a *Autopilot) Evaluate(ctx context.Context) error {
	a.run.Lock()
	defer a.run.Unlock()
	ups, err := a.Store.Upstreams(ctx)
	if err != nil {
		return err
	}
	now := a.now()
	mode := a.mode(ctx)
	ix := a.currentIndex()
	owners := NewUpstreamIndex(ups)
	results := make(map[int64]Result, len(ups))
	blocked := map[int64]string{}
	var rules []lists.Rule
	for _, u := range ups {
		if ix == nil {
			continue
		}
		r := ix.Check(u)
		results[u.ID] = r
		if r.Standing != u.Standing {
			a.note(ctx, store.ComplianceEntry{At: now, UpstreamID: u.ID, Upstream: u.Name, Standing: r.Standing, Action: ActionStanding, Detail: Describe(u, r)}, r)
			if err := a.Store.SetUpstreamStanding(ctx, u.ID, r.Standing, now); err != nil {
				return err
			}
			if Bad(r.Standing) {
				a.alert(ctx, u, r, mode)
			}
		}
		if mode == ModeEnforce && r.Blocks() {
			blocked[u.ID] = u.Name
			rules = append(rules, rulesFor(u, r, now)...)
		}
	}
	if mode == ModeEnforce && ix == nil {
		a.publish(results, owners, now)
		return nil
	}
	prev := a.loadBlocked(ctx)
	for id, name := range blocked {
		if _, ok := prev[id]; !ok {
			r := results[id]
			a.note(ctx, store.ComplianceEntry{At: now, UpstreamID: id, Upstream: name, Standing: r.Standing, Action: ActionBlocked, Detail: rulesPhrase(countRules(rules, id))}, r)
		}
	}
	for id, name := range prev {
		if _, ok := blocked[id]; !ok {
			r := results[id]
			why := "The upstream is no longer under an FCC order."
			if mode != ModeEnforce {
				why = "The autopilot is in monitor mode."
			} else if _, still := results[id]; !still {
				why = "The upstream was removed from the registry."
			}
			a.note(ctx, store.ComplianceEntry{At: now, UpstreamID: id, Upstream: name, Standing: r.Standing, Action: ActionReleased, Detail: "Deny rules removed. " + why}, r)
		}
	}
	if err := a.Store.ReplaceOriginRules(ctx, RuleOrigin, rules); err != nil {
		return err
	}
	b, _ := json.Marshal(blocked)
	if err := a.Store.KVSet(ctx, kvBlocked, string(b)); err != nil {
		return err
	}
	if a.Reload != nil {
		if err := a.Reload(ctx); err != nil {
			return err
		}
	}
	a.publish(results, owners, now)
	return nil
}

func (a *Autopilot) publish(results map[int64]Result, owners *UpstreamIndex, now time.Time) {
	a.state.Lock()
	a.results, a.owners, a.checked = results, owners, now
	a.state.Unlock()
}

// rulesFor is one deny rule per address and signer code of the upstream.
// Each rule carries the order, so the Rules page and the call view say why.
func rulesFor(u store.Upstream, r Result, now time.Time) []lists.Rule {
	note := fmt.Sprintf("FCC autopilot #%d: %s, %s", u.ID, u.Name, Words(r))
	var out []lists.Rule
	for _, ip := range u.IPs {
		out = append(out, lists.Rule{Kind: lists.Deny, Subject: lists.IP, Value: ip, Note: note, Origin: RuleOrigin, CreatedAt: now})
	}
	for _, spc := range u.SPCs {
		out = append(out, lists.Rule{Kind: lists.Deny, Subject: lists.SPC, Value: spc, Note: note, Origin: RuleOrigin, CreatedAt: now})
	}
	return out
}

func countRules(rules []lists.Rule, id int64) int {
	tag := fmt.Sprintf("#%d:", id)
	n := 0
	for _, r := range rules {
		if strings.Contains(r.Note, tag) {
			n++
		}
	}
	return n
}

func (a *Autopilot) loadBlocked(ctx context.Context) map[int64]string {
	out := map[int64]string{}
	if raw, _ := a.Store.KVGet(ctx, kvBlocked); raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

func (a *Autopilot) note(ctx context.Context, e store.ComplianceEntry, r Result) {
	if r.Provider != nil {
		e.Provider, e.Doc = r.Provider.Name, r.Provider.OrderDoc
	}
	if _, err := a.Store.AddComplianceEntry(ctx, e); err != nil {
		log.Printf("falcon fcc: log: %v", err)
	}
}

func (a *Autopilot) alert(ctx context.Context, u store.Upstream, r Result, mode string) {
	if a.Alert == nil {
		return
	}
	sev, title := "critical", fmt.Sprintf("Upstream %s: %s", u.Name, Words(r))
	detail := Describe(u, r)
	switch {
	case !r.Confirmed:
		sev = "warning"
		title = fmt.Sprintf("Upstream %s may be %s: %s", u.Name, providerName(r), Words(r))
		detail += " Add its RMD number or FRN to confirm. Falcon does not block on a name."
	case mode == ModeEnforce:
		detail += " Falcon rejects its calls now."
	default:
		detail += " Falcon is in monitor mode, so its calls still pass. Turn on enforcement in Settings, FCC autopilot."
	}
	a.Alert(ctx, alerts.Fired{
		Key: fmt.Sprintf("fcc:%d:%s", u.ID, r.Standing), Severity: sev, Title: title, Detail: detail,
		Data: map[string]any{"upstream_id": u.ID, "upstream": u.Name, "standing": r.Standing, "confirmed": r.Confirmed, "order": orderDoc(r), "since": r.Since},
	})
}

// Words is the standing in a short phrase.
func Words(r Result) string {
	doc := orderDoc(r)
	switch r.Standing {
	case Blocked:
		return "under FCC block order " + doc
	case Removed:
		return "removed from the Robocall Mitigation Database by FCC order " + doc
	case Unlisted:
		if r.Since != "" {
			return "not in the Robocall Mitigation Database since " + r.Since
		}
		return "not in the Robocall Mitigation Database"
	case Listed:
		return "in the Robocall Mitigation Database"
	case NotFound:
		return "RMD number or FRN not found"
	default:
		return "no RMD number or FRN"
	}
}

// Describe says what the standing means for the operator.
func Describe(u store.Upstream, r Result) string {
	switch r.Standing {
	case Blocked:
		return fmt.Sprintf("%s is named in FCC final determination order %s. Under 47 CFR 64.1200(n)(3), downstream providers must block its traffic.", providerName(r), orderDoc(r))
	case Removed:
		return fmt.Sprintf("FCC order %s removed %s from the Robocall Mitigation Database. Under 47 CFR 64.6305(g), you may not accept its calls directly.", orderDoc(r), providerName(r))
	case Unlisted:
		return fmt.Sprintf("%s is no longer in the Robocall Mitigation Database. Under 47 CFR 64.6305(g), you may not accept its calls directly.", providerName(r))
	case NotFound:
		return fmt.Sprintf("The RMD number or FRN of %s is not in the Robocall Mitigation Database. Check the number.", u.Name)
	case Listed:
		return fmt.Sprintf("%s is in the Robocall Mitigation Database with no FCC order.", providerName(r))
	default:
		return fmt.Sprintf("%s has no RMD number or FRN, and no provider in the database has that name.", u.Name)
	}
}

func providerName(r Result) string {
	if r.Provider != nil && r.Provider.Name != "" {
		return r.Provider.Name
	}
	return "The provider"
}

func orderDoc(r Result) string {
	if r.Provider != nil {
		return r.Provider.OrderDoc
	}
	return ""
}

func rulesPhrase(n int) string {
	switch n {
	case 0:
		return "No deny rules: the upstream has no addresses or signer codes. Add them in Rules."
	case 1:
		return "Deny rule added for 1 address or signer code."
	default:
		return fmt.Sprintf("Deny rules added for %d addresses and signer codes.", n)
	}
}

func (a *Autopilot) mode(ctx context.Context) string {
	if a.Mode != nil && a.Mode(ctx) == ModeEnforce {
		return ModeEnforce
	}
	return ModeMonitor
}

func (a *Autopilot) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

func (a *Autopilot) currentIndex() *Index {
	a.state.RLock()
	defer a.state.RUnlock()
	return a.index
}

// Status is the list state for Settings.
func (a *Autopilot) Status() Status {
	a.state.RLock()
	defer a.state.RUnlock()
	st := Status{Source: a.SourceName, LoadedAt: a.loadedAt, CheckedAt: a.checked, Error: a.err}
	if a.index != nil {
		st.Providers, st.GeneratedAt = a.index.Count(), a.index.GeneratedAt()
	} else if a.Source == nil && st.Error == "" {
		st.Error = "no list source. Share telemetry, set CALLERAPI_API_KEY, or set FALCON_FCC_FILE"
	}
	return st
}

// Result is the last check of one upstream.
func (a *Autopilot) Result(id int64) (Result, bool) {
	a.state.RLock()
	defer a.state.RUnlock()
	r, ok := a.results[id]
	return r, ok
}

// Signer returns the standing of the provider named on a signing
// certificate. It never blocks: the signer may not be the upstream.
func (a *Autopilot) Signer(name string) (Result, bool) {
	ix := a.currentIndex()
	if ix == nil || strings.TrimSpace(name) == "" {
		return Result{}, false
	}
	return ix.ByName(name)
}

// Owner returns the upstream that owns a source address or signer code.
func (a *Autopilot) Owner(ip, spc string) (store.Upstream, bool) {
	a.state.RLock()
	owners := a.owners
	a.state.RUnlock()
	return owners.Find(ip, spc)
}
