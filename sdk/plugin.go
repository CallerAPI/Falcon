// Package sdk is the contract a Falcon plugin uses.
//
// A plugin names the input fields it may read and returns a decision patch.
// Falcon ships this vocabulary. A new plugin that stays inside it does not
// need a new Falcon binary. CallerAPI loads the plugin and Falcon fetches
// the catalog.
//
// The called number, the raw SIP message, and the Identity header are not
// fields. A plugin cannot ask for them.
package sdk

import (
	"net/url"
	"strings"
	"unicode"
)

// Fields a plugin may name in its input list.
var Fields = []string{
	"from",
	"source_ip",
	"user_agent",
	"call_id",
	"attest",
	"verstat",
	"signer_spc",
	"signer_name",
	"provider",
	"fingerprint",
	"direction",
	"method",
	"action",
	"score",
	"reason_codes",
}

// Input is one screening, restricted to Fields.
type Input struct {
	From        string `json:"from,omitempty"`
	SourceIP    string `json:"source_ip,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
	CallID      string `json:"call_id,omitempty"`
	Attest      string `json:"attest,omitempty"`
	Verstat     string `json:"verstat,omitempty"`
	SignerSPC   string `json:"signer_spc,omitempty"`
	SignerName  string `json:"signer_name,omitempty"`
	Provider    string `json:"provider,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Direction   string `json:"direction,omitempty"`
	Method      string `json:"method,omitempty"`
	Action      string `json:"action,omitempty"`
	Score       string `json:"score,omitempty"`
	ReasonCodes string `json:"reason_codes,omitempty"`
}

// Output is the patch a plugin returns. Action empty means do not change
// the decision. Weight is added to the score and capped at 100.
type Output struct {
	Weight int    `json:"weight"`
	Reason string `json:"reason,omitempty"`
	Action string `json:"action,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Manifest is one catalog row Falcon is allowed to see. Partner addresses
// stay on CallerAPI.
//
// Surface is empty, native, or iframe. A native surface is a table or a
// row of stats that Falcon draws. An iframe surface is a page on the
// CallerAPI host. Kind view never runs during screening.
type Manifest struct {
	Slug     string   `json:"slug"`
	Title    string   `json:"title,omitempty"`
	Kind     string   `json:"kind"`
	Surface  string   `json:"surface,omitempty"`
	Widget   string   `json:"widget,omitempty"`
	Inputs   []string `json:"inputs"`
	KeyField string   `json:"key_field"`
	Mode     string   `json:"mode"`
	Timeout  int      `json:"timeout_ms"`
}

// Column is one native table column.
type Column struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// Stat is one native summary figure.
type Stat struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Panel is the dashboard payload for one plugin. FrameURL is set only for
// an iframe surface, and only when it is on the CallerAPI host.
type Panel struct {
	Title       string              `json:"title"`
	Surface     string              `json:"surface"`
	Widget      string              `json:"widget"`
	Columns     []Column            `json:"columns,omitempty"`
	Rows        []map[string]string `json:"rows,omitempty"`
	Stats       []Stat              `json:"stats,omitempty"`
	FrameURL    string              `json:"frame_url,omitempty"`
	FrameOrigin string              `json:"frame_origin,omitempty"`
	Import      bool                `json:"import,omitempty"`
}

// Known reports whether name is a field a plugin may request.
func Known(name string) bool {
	for _, f := range Fields {
		if f == name {
			return true
		}
	}
	return false
}

// Select copies only the allowed known fields. Unknown names are dropped.
func Select(all map[string]string, allow []string) map[string]string {
	out := map[string]string{}
	for _, name := range allow {
		if !Known(name) {
			continue
		}
		if v, ok := all[name]; ok && v != "" {
			out[name] = v
		}
	}
	return out
}

// AsMap returns every non-empty field. Callers still pass the result
// through Select before it leaves the process.
func (in Input) AsMap() map[string]string {
	all := map[string]string{
		"from": in.From, "source_ip": in.SourceIP, "user_agent": in.UserAgent,
		"call_id": in.CallID, "attest": in.Attest, "verstat": in.Verstat,
		"signer_spc": in.SignerSPC, "signer_name": in.SignerName, "provider": in.Provider,
		"fingerprint": in.Fingerprint, "direction": in.Direction, "method": in.Method,
		"action": in.Action, "score": in.Score, "reason_codes": in.ReasonCodes,
	}
	return Select(all, Fields)
}

// CleanQuery keeps an operator search short and plain.
func CleanQuery(q string) string {
	q = strings.TrimSpace(q)
	if strings.ContainsAny(q, "<>\r\n") {
		return ""
	}
	if len(q) > 64 {
		q = q[:64]
	}
	return q
}

// SameOrigin reports whether raw is an http(s) URL on the same host as base.
// The path must stay under the Falcon plugin prefix.
func SameOrigin(base, raw string) bool {
	b, err := url.Parse(strings.TrimSpace(base))
	if err != nil || b.Host == "" || (b.Scheme != "https" && b.Scheme != "http") || b.User != nil {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	if u.Scheme != b.Scheme || !strings.EqualFold(u.Host, b.Host) {
		return false
	}
	return strings.HasPrefix(u.Path, "/api/falcon/v1/plugins/")
}

// FrameOrigin is the CSP frame-src value for base. An empty result means
// the dashboard does not embed a frame.
func FrameOrigin(base string) string {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// SanitizePanel keeps a native panel inside the widget vocabulary.
func SanitizePanel(p Panel) Panel {
	out := Panel{
		Title:   clipText(p.Title, 80),
		Surface: p.Surface,
		Widget:  p.Widget,
	}
	if out.Surface != "native" && out.Surface != "iframe" {
		out.Surface = ""
	}
	if out.Widget != "table" && out.Widget != "stats" {
		out.Widget = "table"
	}
	if out.Surface == "iframe" {
		out.FrameURL = strings.TrimSpace(p.FrameURL)
		return out
	}
	out.Import = p.Import && out.Surface == "native"
	if len(p.Columns) > 8 {
		p.Columns = p.Columns[:8]
	}
	for _, col := range p.Columns {
		key := columnKey(col.Key)
		if key == "" {
			continue
		}
		out.Columns = append(out.Columns, Column{Key: key, Label: clipText(col.Label, 40)})
	}
	if len(p.Rows) > 50 {
		p.Rows = p.Rows[:50]
	}
	for _, row := range p.Rows {
		clean := map[string]string{}
		for _, col := range out.Columns {
			if v, ok := row[col.Key]; ok {
				clean[col.Key] = clipText(v, 80)
			}
		}
		out.Rows = append(out.Rows, clean)
	}
	if len(p.Stats) > 8 {
		p.Stats = p.Stats[:8]
	}
	for _, st := range p.Stats {
		out.Stats = append(out.Stats, Stat{Label: clipText(st.Label, 40), Value: clipText(st.Value, 40)})
	}
	return out
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

func clipText(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " "))
	if len(s) > n {
		s = s[:n]
	}
	return s
}
