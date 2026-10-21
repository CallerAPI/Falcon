package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Traceback case states.
const (
	TracebackOpen     = "open"
	TracebackAnswered = "answered"
)

// TracebackCase is one traceback request: the call it names, the clock it
// runs on, what Falcon found, and the answer the operator sent.
type TracebackCase struct {
	ID          int64      `json:"id"`
	Reference   string     `json:"reference,omitempty"`
	From        string     `json:"from"`
	To          string     `json:"to,omitempty"`
	CallAt      time.Time  `json:"call_at"`
	WindowS     int        `json:"window_s"`
	RequestedAt time.Time  `json:"requested_at"`
	DueAt       time.Time  `json:"due_at"`
	AnsweredAt  *time.Time `json:"answered_at,omitempty"`
	Status      string     `json:"status"`
	UpstreamID  int64      `json:"upstream_id,omitempty"`
	Upstream    string     `json:"upstream,omitempty"`
	EventIDs    []int64    `json:"event_ids"`
	Answer      string     `json:"answer,omitempty"`
	Note        string     `json:"note,omitempty"`
}

// SourceTraffic is the inbound traffic from one source address and signer
// code in a window.
type SourceTraffic struct {
	SourceIP     string `json:"source_ip"`
	SPC          string `json:"spc"`
	Calls        int    `json:"calls"`
	Blocked      int    `json:"blocked"`
	Flagged      int    `json:"flagged"`
	SpamHits     int    `json:"spam_hits"`
	Honeypots    int    `json:"honeypots"`
	VerifyFailed int    `json:"verify_failed"`
	Unsigned     int    `json:"unsigned"`
}

// TracebackStore keeps traceback cases and answers the queries they need.
type TracebackStore interface {
	AddTraceback(ctx context.Context, c TracebackCase) (TracebackCase, error)
	UpdateTraceback(ctx context.Context, c TracebackCase) error
	Traceback(ctx context.Context, id int64) (TracebackCase, bool, error)
	Tracebacks(ctx context.Context, limit int) ([]TracebackCase, error)
	TracebacksBetween(ctx context.Context, from, to time.Time) ([]TracebackCase, error)
	FindCalls(ctx context.Context, from, to []string, start, end time.Time, limit int) ([]Event, error)
	SourceTraffic(ctx context.Context, from, to time.Time) ([]SourceTraffic, error)
}

func (s *SQLite) migrateTracebacks() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS tracebacks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reference TEXT NOT NULL DEFAULT '',
  from_num TEXT NOT NULL,
  to_num TEXT NOT NULL DEFAULT '',
  call_unix INTEGER NOT NULL,
  window_s INTEGER NOT NULL,
  requested_unix INTEGER NOT NULL,
  due_unix INTEGER NOT NULL,
  answered_unix INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'open',
  upstream_id INTEGER NOT NULL DEFAULT 0,
  upstream TEXT NOT NULL DEFAULT '',
  event_ids TEXT NOT NULL DEFAULT '',
  answer TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS tracebacks_requested ON tracebacks(requested_unix DESC);`)
	return err
}

const tracebackColumns = `id, reference, from_num, to_num, call_unix, window_s, requested_unix, due_unix, answered_unix, status, upstream_id, upstream, event_ids, answer, note`

func scanTraceback(row interface{ Scan(...any) error }) (TracebackCase, error) {
	var c TracebackCase
	var callAt, requested, due, answered int64
	var ids string
	if err := row.Scan(&c.ID, &c.Reference, &c.From, &c.To, &callAt, &c.WindowS, &requested, &due, &answered, &c.Status, &c.UpstreamID, &c.Upstream, &ids, &c.Answer, &c.Note); err != nil {
		return c, err
	}
	c.CallAt, c.RequestedAt, c.DueAt = time.Unix(callAt, 0).UTC(), time.Unix(requested, 0).UTC(), time.Unix(due, 0).UTC()
	if answered > 0 {
		t := time.Unix(answered, 0).UTC()
		c.AnsweredAt = &t
	}
	c.EventIDs = []int64{}
	for _, v := range strings.Split(ids, ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			c.EventIDs = append(c.EventIDs, id)
		}
	}
	return c, nil
}

func joinIDs(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ",")
}

func unixOrZero(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.Unix()
}

func (s *SQLite) AddTraceback(ctx context.Context, c TracebackCase) (TracebackCase, error) {
	if c.Status == "" {
		c.Status = TracebackOpen
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO tracebacks (reference, from_num, to_num, call_unix, window_s, requested_unix, due_unix, answered_unix, status, upstream_id, upstream, event_ids, answer, note)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Reference, c.From, c.To, c.CallAt.Unix(), c.WindowS, c.RequestedAt.Unix(), c.DueAt.Unix(), unixOrZero(c.AnsweredAt), c.Status, c.UpstreamID, c.Upstream, joinIDs(c.EventIDs), c.Answer, c.Note)
	if err != nil {
		return c, err
	}
	c.ID, err = res.LastInsertId()
	return c, err
}

func (s *SQLite) UpdateTraceback(ctx context.Context, c TracebackCase) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tracebacks SET status = ?, answered_unix = ?, answer = ?, note = ?, upstream_id = ?, upstream = ? WHERE id = ?`,
		c.Status, unixOrZero(c.AnsweredAt), c.Answer, c.Note, c.UpstreamID, c.Upstream, c.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no traceback with that id")
	}
	return nil
}

func (s *SQLite) Traceback(ctx context.Context, id int64) (TracebackCase, bool, error) {
	c, err := scanTraceback(s.db.QueryRowContext(ctx, `SELECT `+tracebackColumns+` FROM tracebacks WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return TracebackCase{}, false, nil
	}
	return c, err == nil, err
}

// Tracebacks returns open cases first, the nearest deadline first, then the
// answered ones, newest first.
func (s *SQLite) Tracebacks(ctx context.Context, limit int) ([]TracebackCase, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return s.queryTracebacks(ctx, `SELECT `+tracebackColumns+` FROM tracebacks
ORDER BY status = 'open' DESC, CASE WHEN status = 'open' THEN due_unix ELSE -requested_unix END LIMIT ?`, limit)
}

// TracebacksBetween returns the cases requested in [from, to).
func (s *SQLite) TracebacksBetween(ctx context.Context, from, to time.Time) ([]TracebackCase, error) {
	return s.queryTracebacks(ctx, `SELECT `+tracebackColumns+` FROM tracebacks WHERE requested_unix >= ? AND requested_unix < ? ORDER BY requested_unix`, from.Unix(), to.Unix())
}

func (s *SQLite) queryTracebacks(ctx context.Context, q string, args ...any) ([]TracebackCase, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TracebackCase{}
	for rows.Next() {
		c, err := scanTraceback(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// FindCalls returns the calls from one of the from numbers in [start, end],
// with full SIP. When to is not empty the called number must be one of them.
func (s *SQLite) FindCalls(ctx context.Context, from, to []string, start, end time.Time, limit int) ([]Event, error) {
	if len(from) == 0 {
		return nil, errors.New("a calling number is required")
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	where := []string{"received_unix >= ?", "received_unix <= ?", "from_num IN (" + placeholders(len(from)) + ")"}
	args := []any{start.Unix(), end.Unix()}
	for _, v := range from {
		args = append(args, v)
	}
	if len(to) > 0 {
		where = append(where, "to_num IN ("+placeholders(len(to))+")")
		for _, v := range to {
			args = append(args, v)
		}
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, selectEvents(true)+" WHERE "+strings.Join(where, " AND ")+" ORDER BY id DESC LIMIT ?", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// SourceTraffic groups inbound calls in [from, to) by source address and
// signer code. The caller maps each group to an upstream.
func (s *SQLite) SourceTraffic(ctx context.Context, from, to time.Time) ([]SourceTraffic, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT COALESCE(source_ip, ''), COALESCE(signer_spc, ''), COUNT(*),
  SUM(CASE WHEN action = 'reject' THEN 1 ELSE 0 END),
  SUM(CASE WHEN action IN ('flag', 'challenge') THEN 1 ELSE 0 END),
  SUM(CASE WHEN reasons LIKE '%"spam_feed_hit"%' THEN 1 ELSE 0 END),
  SUM(CASE WHEN COALESCE(honeypot, 0) = 1 THEN 1 ELSE 0 END),
  SUM(CASE WHEN COALESCE(verstat, '') = 'TN-Validation-Failed' THEN 1 ELSE 0 END),
  SUM(CASE WHEN COALESCE(attest, '') IN ('', 'C') THEN 1 ELSE 0 END)
FROM events
WHERE received_unix >= ? AND received_unix < ? AND COALESCE(direction, '') != 'outbound'
GROUP BY 1, 2`, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SourceTraffic{}
	for rows.Next() {
		var t SourceTraffic
		if err := rows.Scan(&t.SourceIP, &t.SPC, &t.Calls, &t.Blocked, &t.Flagged, &t.SpamHits, &t.Honeypots, &t.VerifyFailed, &t.Unsigned); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
