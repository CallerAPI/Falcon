package httpapi

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/compliance"
	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/traceback"
)

// tracebackView is a case with its clock and the calls Falcon matched.
type tracebackView struct {
	store.TracebackCase
	Overdue bool        `json:"overdue"`
	PackURL string      `json:"pack_url,omitempty"`
	Calls   []callBrief `json:"calls,omitempty"`
}

// callBrief is a matched call without its SIP message.
type callBrief struct {
	ID         int64     `json:"id"`
	ReceivedAt time.Time `json:"received_at"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	SourceIP   string    `json:"source_ip"`
	Action     string    `json:"action"`
	Attest     string    `json:"attest,omitempty"`
	SignerSPC  string    `json:"signer_spc,omitempty"`
	CallID     string    `json:"call_id,omitempty"`
}

func brief(ev store.Event) callBrief {
	return callBrief{ID: ev.ID, ReceivedAt: ev.ReceivedAt, From: ev.From, To: ev.To, SourceIP: ev.SourceIP, Action: string(ev.Action), Attest: ev.Attest, SignerSPC: ev.SignerSPC, CallID: ev.CallID}
}

func (s *Server) tracebackView(c store.TracebackCase, calls []store.Event) tracebackView {
	v := tracebackView{TracebackCase: c, Overdue: c.Status == store.TracebackOpen && time.Now().After(c.DueAt)}
	number := c.From
	for _, ev := range calls {
		v.Calls = append(v.Calls, brief(ev))
		number = ev.From
	}
	window := time.Duration(c.WindowS) * time.Second
	v.PackURL = "/v1/traceback.zip?number=" + url.QueryEscape(number) +
		"&from=" + url.QueryEscape(c.CallAt.Add(-window).Format(time.RFC3339)) + "&to=" + url.QueryEscape(c.CallAt.Add(window).Format(time.RFC3339))
	return v
}

// upstreamOwners indexes the registry as it is now.
func (s *Server) upstreamOwners(ctx context.Context) ([]store.Upstream, *compliance.UpstreamIndex, error) {
	ups, err := s.Store.Upstreams(ctx)
	if err != nil {
		return nil, nil, err
	}
	return ups, compliance.NewUpstreamIndex(ups), nil
}

func (s *Server) standingWords(id int64) string {
	return s.reportStanding(id).Text
}

func (s *Server) reportStanding(id int64) traceback.Standing {
	if s.Compliance == nil {
		return traceback.Standing{}
	}
	if r, ok := s.Compliance.Result(id); ok {
		return traceback.Standing{Code: r.Standing, Confirmed: r.Confirmed, Text: compliance.Words(r)}
	}
	return traceback.Standing{}
}

func parseCallTime(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02 15:04"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("time %q is not RFC 3339 or YYYY-MM-DD HH:MM:SS in UTC", v)
}

func (s *Server) handleTracebackCases(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		cases, err := s.Store.Tracebacks(r.Context(), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out := make([]tracebackView, 0, len(cases))
		for _, c := range cases {
			out = append(out, s.tracebackView(c, nil))
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": out})
	case http.MethodPost:
		s.openTraceback(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST"})
	}
}

// openTraceback logs a request, finds the call, and writes the answer.
func (s *Server) openTraceback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reference     string `json:"reference"`
		From          string `json:"from"`
		To            string `json:"to"`
		CallAt        string `json:"call_at"`
		WindowMinutes int    `json:"window_minutes"`
		RequestedAt   string `json:"requested_at"`
		Note          string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	fromForms, toForms := traceback.Variants(body.From), traceback.Variants(body.To)
	if len(fromForms) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from must be the calling number"})
		return
	}
	callAt, err := parseCallTime(body.CallAt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	now := time.Now().UTC()
	requested := now
	if strings.TrimSpace(body.RequestedAt) != "" {
		if requested, err = parseCallTime(body.RequestedAt); err != nil || requested.After(now.Add(5*time.Minute)) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "requested_at must be a past time in UTC"})
			return
		}
	}
	window := traceback.DefaultWindow
	if body.WindowMinutes != 0 {
		if body.WindowMinutes < 1 || body.WindowMinutes > 120 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "window_minutes must be between 1 and 120"})
			return
		}
		window = time.Duration(body.WindowMinutes) * time.Minute
	}
	c := store.TracebackCase{
		Reference: clipText(body.Reference, 100), From: fromForms[len(fromForms)-1], CallAt: callAt, WindowS: int(window / time.Second),
		RequestedAt: requested, DueAt: requested.Add(traceback.Deadline), Status: store.TracebackOpen, Note: clipText(body.Note, 500),
	}
	if len(toForms) > 0 {
		c.To = toForms[len(toForms)-1]
	}
	calls, err := s.Store.FindCalls(r.Context(), fromForms, toForms, callAt.Add(-window), callAt.Add(window), 50)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	found := traceback.Found{RetentionDays: s.Settings(r.Context()).RetentionDays}
	if best, ok := traceback.Pick(calls, callAt); ok {
		found.Event = &best
		for _, ev := range calls {
			c.EventIDs = append(c.EventIDs, ev.ID)
		}
		if best.Direction != "outbound" {
			if _, owners, err := s.upstreamOwners(r.Context()); err == nil {
				if u, ok := owners.Find(best.SourceIP, best.SignerSPC); ok {
					c.UpstreamID, c.Upstream = u.ID, u.Name
					found.Upstream, found.Standing = &u, s.standingWords(u.ID)
				}
			}
		}
	}
	c.Answer = traceback.Answer(c, found)
	saved, err := s.Store.AddTraceback(r.Context(), c)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "traceback.open", firstNonEmpty(saved.Reference, saved.From), fmt.Sprintf("#%d, %d calls, upstream %q", saved.ID, len(calls), saved.Upstream))
	writeJSON(w, http.StatusCreated, s.tracebackView(saved, calls))
}

func (s *Server) handleTracebackCase(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/v1/tracebacks/"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	c, ok, err := s.Store.Traceback(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no traceback with that id"})
		return
	}
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost, http.MethodPut:
		var body struct {
			Status *string `json:"status"`
			Answer *string `json:"answer"`
			Note   *string `json:"note"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		if body.Answer != nil {
			c.Answer = clipText(*body.Answer, 8000)
		}
		if body.Note != nil {
			c.Note = clipText(*body.Note, 500)
		}
		if body.Status != nil {
			switch *body.Status {
			case store.TracebackAnswered:
				if c.AnsweredAt == nil {
					now := time.Now().UTC()
					c.AnsweredAt = &now
				}
			case store.TracebackOpen:
				c.AnsweredAt = nil
			default:
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be open or answered"})
				return
			}
			c.Status = *body.Status
		}
		if err := s.Store.UpdateTraceback(r.Context(), c); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.audit(r, "traceback."+c.Status, firstNonEmpty(c.Reference, c.From), fmt.Sprintf("#%d", c.ID))
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST"})
		return
	}
	var calls []store.Event
	for i, eid := range c.EventIDs {
		if i == 50 {
			break
		}
		if ev, err := s.Store.Get(r.Context(), eid); err == nil {
			calls = append(calls, ev)
		}
	}
	writeJSON(w, http.StatusOK, s.tracebackView(c, calls))
}

// handleUpstreamReport is the traffic of each upstream for one month, with
// its FCC standing and its traceback cases. The CSV is the file an operator
// keeps as evidence that it knows its upstreams.
func (s *Server) handleUpstreamReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}
	month := strings.TrimSpace(r.URL.Query().Get("month"))
	start := time.Now().UTC()
	start = time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC)
	if month != "" {
		t, err := time.Parse("2006-01", month)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "month must be YYYY-MM"})
			return
		}
		start = t.UTC()
	}
	end := start.AddDate(0, 1, 0)
	ctx := r.Context()
	traffic, err := s.Store.SourceTraffic(ctx, start, end)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	cases, err := s.Store.TracebacksBetween(ctx, start, end)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	ups, owners, err := s.upstreamOwners(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rows := traceback.Report(traffic, ups, owners.Find, s.reportStanding, cases)
	if !strings.HasSuffix(r.URL.Path, ".csv") {
		writeJSON(w, http.StatusOK, map[string]any{"month": start.Format("2006-01"), "from": start, "to": end, "data": rows})
		return
	}
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	_ = cw.Write([]string{"upstream", "rmd_number", "frn", "fcc_standing", "calls", "blocked", "flagged", "spam_list_hits", "honeypot_hits", "failed_verification", "unsigned_or_attestation_c", "traceback_requests"})
	for _, row := range rows {
		_ = cw.Write([]string{row.Name, row.RMD, row.FRN, row.StandingText, strconv.Itoa(row.Calls), strconv.Itoa(row.Blocked), strconv.Itoa(row.Flagged),
			strconv.Itoa(row.SpamHits), strconv.Itoa(row.Honeypots), strconv.Itoa(row.VerifyFailed), strconv.Itoa(row.Unsigned), strconv.Itoa(row.Tracebacks)})
	}
	cw.Flush()
	s.audit(r, "report.export", start.Format("2006-01"), fmt.Sprintf("%d upstreams", len(rows)))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="falcon-upstreams-`+start.Format("2006-01")+`.csv"`)
	_, _ = w.Write(buf.Bytes())
}

// tracebackInsights puts every open case on the home screen with its clock.
func (s *Server) tracebackInsights(ctx context.Context, add adder) {
	cases, err := s.Store.Tracebacks(ctx, 50)
	if err != nil {
		return
	}
	now := time.Now()
	for _, c := range cases {
		if c.Status != store.TracebackOpen {
			continue
		}
		name := c.Reference
		if name == "" {
			name = "for " + c.From
		}
		left := c.DueAt.Sub(now)
		sev, title := sevWarning, fmt.Sprintf("Traceback %s is due in %s", name, hoursLeft(left))
		if left < 6*time.Hour {
			sev = sevCritical
		}
		if left <= 0 {
			title = fmt.Sprintf("Traceback %s is overdue", name)
		}
		detail := "Falcon found no matching call. The answer says so. Check the numbers and the time."
		switch {
		case c.Upstream != "":
			detail = "Falcon found the call. It came from " + c.Upstream + ". The answer is ready to send."
		case len(c.EventIDs) > 0:
			detail = "Falcon found the call. Its address is not in the upstream registry. The answer is ready to send."
		}
		add(Insight{Key: "traceback:" + strconv.FormatInt(c.ID, 10), Severity: sev, Title: title, Detail: detail, Link: "#threats?tab=tracebacks", LinkText: "Open the answer"})
	}
}

func hoursLeft(d time.Duration) string {
	h := int(d.Round(time.Hour) / time.Hour)
	switch {
	case d < time.Hour:
		return "less than an hour"
	case h == 1:
		return "1 hour"
	default:
		return strconv.Itoa(h) + " hours"
	}
}

func clipText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}
