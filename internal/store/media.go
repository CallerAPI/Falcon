package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// MediaCall is one call the bridge carried: the signaling times, who hung
// up, what the FAS guard heard, and where the recording is. Times are
// milliseconds after the INVITE reached Falcon.
type MediaCall struct {
	ID         int64     `json:"id"`
	EventID    int64     `json:"event_id"`
	CallID     string    `json:"call_id"`
	LegBCallID string    `json:"leg_b_call_id,omitempty"`
	Route      string    `json:"route,omitempty"`
	Carry      string    `json:"carry"`
	From       string    `json:"from,omitempty"`
	To         string    `json:"to,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	RingMS     int       `json:"ring_ms,omitempty"`
	AnswerMS   int       `json:"answer_ms,omitempty"`
	ConnectMS  int       `json:"connect_ms,omitempty"`
	EndMS      int       `json:"end_ms,omitempty"`
	EndedBy    string    `json:"ended_by,omitempty"`
	Status     int       `json:"status"`
	Codec      string    `json:"codec,omitempty"`
	// FAS is empty for a clean answer, else ringback, busy, sit,
	// dead_air, or instant. FASMS is the billed time that was not a
	// conversation. FASAction is observed, held, or failed.
	FAS       string          `json:"fas,omitempty"`
	FASMS     int             `json:"fas_ms,omitempty"`
	FASAction string          `json:"fas_action,omitempty"`
	FASDetail json.RawMessage `json:"fas_detail,omitempty"`
	Recording string          `json:"-"`
	Seconds   float64         `json:"seconds,omitempty"`
	PacketsA  int64           `json:"packets_a"`
	PacketsB  int64           `json:"packets_b"`
}

// Route sends calls with a tech prefix to a labeled vendor path. Target
// empty sends the call back to the switch that sent it, which routes the
// prefix to that vendor. Carry is all or suspicious.
type Route struct {
	ID        int64     `json:"id"`
	Prefix    string    `json:"prefix"`
	Label     string    `json:"label"`
	Strip     bool      `json:"strip"`
	Target    string    `json:"target,omitempty"`
	Carry     string    `json:"carry"`
	CreatedAt time.Time `json:"created_at"`
}

// Carry policies for a route.
const (
	CarryAll        = "all"
	CarrySuspicious = "suspicious"
)

// RouteStat is the answer quality of one route over a window.
type RouteStat struct {
	Route      string    `json:"route"`
	Calls      int       `json:"calls"`
	Answered   int       `json:"answered"`
	FAS        int       `json:"fas"`
	FASSeconds float64   `json:"fas_seconds"`
	AvgRingMS  int       `json:"avg_ring_ms"`
	TalkSec    float64   `json:"talk_seconds"`
	LastFAS    time.Time `json:"last_fas,omitempty"`
	ByKind     []KindN   `json:"by_kind"`
}

// KindN counts one FAS kind.
type KindN struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// MediaTotals summarise the bridge over a window.
type MediaTotals struct {
	Bridged    int     `json:"bridged"`
	Answered   int     `json:"answered"`
	Recorded   int     `json:"recorded"`
	FAS        int     `json:"fas"`
	FASSeconds float64 `json:"fas_seconds"`
	FASHeld    int     `json:"fas_held"`
}

// LatencyStats is the time Falcon held INVITEs in a window.
type LatencyStats struct {
	Count int     `json:"count"`
	AvgMS float64 `json:"avg_ms"`
	P50MS float64 `json:"p50_ms"`
	P95MS float64 `json:"p95_ms"`
}

// MediaStore keeps what the bridge did.
type MediaStore interface {
	InsertMediaCall(ctx context.Context, m MediaCall) (int64, error)
	UpdateMediaCall(ctx context.Context, m MediaCall) error
	MediaCallByCallID(ctx context.Context, callID string) (MediaCall, bool, error)
	MediaCall(ctx context.Context, id int64) (MediaCall, bool, error)
	MediaTotals(ctx context.Context, from, to time.Time) (MediaTotals, error)
	RouteStats(ctx context.Context, from, to time.Time) ([]RouteStat, error)
	ExpiredRecordings(ctx context.Context, before time.Time, limit int) ([]MediaCall, error)
	ClearRecording(ctx context.Context, id int64) error
	Routes(ctx context.Context) ([]Route, error)
	PutRoute(ctx context.Context, r Route) (Route, error)
	DeleteRoute(ctx context.Context, id int64) error
	Latency(ctx context.Context, from, to time.Time) (LatencyStats, error)
}

func (s *SQLite) migrateMedia() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS media_calls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL DEFAULT 0,
  call_id TEXT NOT NULL,
  leg_b_call_id TEXT,
  route TEXT,
  carry TEXT,
  from_num TEXT,
  to_num TEXT,
  started_unix INTEGER NOT NULL,
  ring_ms INTEGER NOT NULL DEFAULT 0,
  answer_ms INTEGER NOT NULL DEFAULT 0,
  connect_ms INTEGER NOT NULL DEFAULT 0,
  end_ms INTEGER NOT NULL DEFAULT 0,
  ended_by TEXT,
  status INTEGER NOT NULL DEFAULT 0,
  codec TEXT,
  fas TEXT,
  fas_ms INTEGER NOT NULL DEFAULT 0,
  fas_action TEXT,
  fas_detail TEXT,
  recording TEXT,
  seconds REAL NOT NULL DEFAULT 0,
  packets_a INTEGER NOT NULL DEFAULT 0,
  packets_b INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS media_calls_call_id ON media_calls(call_id);
CREATE INDEX IF NOT EXISTS media_calls_started ON media_calls(started_unix DESC);
CREATE INDEX IF NOT EXISTS media_calls_route ON media_calls(route, started_unix DESC);
CREATE TABLE IF NOT EXISTS routes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  prefix TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  strip INTEGER NOT NULL DEFAULT 0,
  target TEXT,
  carry TEXT NOT NULL DEFAULT 'all',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_latency ON events(received_unix, latency_us);`)
	return err
}

const mediaColumns = `id, event_id, call_id, COALESCE(leg_b_call_id, ''), COALESCE(route, ''), COALESCE(carry, ''),
 COALESCE(from_num, ''), COALESCE(to_num, ''), started_unix, ring_ms, answer_ms, connect_ms, end_ms,
 COALESCE(ended_by, ''), status, COALESCE(codec, ''), COALESCE(fas, ''), fas_ms, COALESCE(fas_action, ''),
 COALESCE(fas_detail, ''), COALESCE(recording, ''), seconds, packets_a, packets_b`

func scanMedia(row rowScanner) (MediaCall, error) {
	var m MediaCall
	var started int64
	var detail string
	err := row.Scan(&m.ID, &m.EventID, &m.CallID, &m.LegBCallID, &m.Route, &m.Carry, &m.From, &m.To, &started,
		&m.RingMS, &m.AnswerMS, &m.ConnectMS, &m.EndMS, &m.EndedBy, &m.Status, &m.Codec, &m.FAS, &m.FASMS, &m.FASAction,
		&detail, &m.Recording, &m.Seconds, &m.PacketsA, &m.PacketsB)
	m.StartedAt = time.UnixMilli(started).UTC()
	if strings.HasPrefix(strings.TrimSpace(detail), "{") || strings.HasPrefix(strings.TrimSpace(detail), "[") {
		m.FASDetail = json.RawMessage(detail)
	}
	return m, err
}

// InsertMediaCall stores a bridged call when it starts.
func (s *SQLite) InsertMediaCall(ctx context.Context, m MediaCall) (int64, error) {
	if m.StartedAt.IsZero() {
		m.StartedAt = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO media_calls
 (event_id, call_id, leg_b_call_id, route, carry, from_num, to_num, started_unix, status)
 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.EventID, m.CallID, m.LegBCallID, m.Route, m.Carry, m.From, m.To, m.StartedAt.UnixMilli(), m.Status)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateMediaCall writes the final state of a bridged call.
func (s *SQLite) UpdateMediaCall(ctx context.Context, m MediaCall) error {
	if m.ID == 0 {
		return errors.New("media call id required")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE media_calls SET
 event_id = CASE WHEN ? > 0 THEN ? ELSE event_id END,
 leg_b_call_id = ?, ring_ms = ?, answer_ms = ?, connect_ms = ?, end_ms = ?, ended_by = ?, status = ?, codec = ?,
 fas = ?, fas_ms = ?, fas_action = ?, fas_detail = ?, recording = ?, seconds = ?, packets_a = ?, packets_b = ?
 WHERE id = ?`,
		m.EventID, m.EventID, m.LegBCallID, m.RingMS, m.AnswerMS, m.ConnectMS, m.EndMS, m.EndedBy, m.Status, m.Codec,
		m.FAS, m.FASMS, m.FASAction, rawText(m.FASDetail), m.Recording, m.Seconds, m.PacketsA, m.PacketsB, m.ID)
	return err
}

// MediaCallByCallID returns the newest bridged call for the switch's Call-ID.
func (s *SQLite) MediaCallByCallID(ctx context.Context, callID string) (MediaCall, bool, error) {
	if strings.TrimSpace(callID) == "" {
		return MediaCall{}, false, nil
	}
	m, err := scanMedia(s.db.QueryRowContext(ctx, `SELECT `+mediaColumns+` FROM media_calls WHERE call_id = ? ORDER BY id DESC LIMIT 1`, callID))
	if err == sql.ErrNoRows {
		return MediaCall{}, false, nil
	}
	return m, err == nil, err
}

// MediaCall returns one bridged call by id.
func (s *SQLite) MediaCall(ctx context.Context, id int64) (MediaCall, bool, error) {
	m, err := scanMedia(s.db.QueryRowContext(ctx, `SELECT `+mediaColumns+` FROM media_calls WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return MediaCall{}, false, nil
	}
	return m, err == nil, err
}

// MediaTotals counts bridged calls, recordings, and false answers.
func (s *SQLite) MediaTotals(ctx context.Context, from, to time.Time) (MediaTotals, error) {
	var t MediaTotals
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),
  COALESCE(SUM(CASE WHEN answer_ms > 0 THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN COALESCE(recording, '') != '' THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN COALESCE(fas, '') != '' THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(fas_ms), 0) / 1000.0,
  COALESCE(SUM(CASE WHEN fas_action IN ('held', 'failed') THEN 1 ELSE 0 END), 0)
FROM media_calls WHERE started_unix >= ? AND started_unix < ?`, from.UnixMilli(), to.UnixMilli()).Scan(
		&t.Bridged, &t.Answered, &t.Recorded, &t.FAS, &t.FASSeconds, &t.FASHeld)
	return t, err
}

// RouteStats groups bridged calls by route. The default path is "".
func (s *SQLite) RouteStats(ctx context.Context, from, to time.Time) ([]RouteStat, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(route, ''), COUNT(*),
  COALESCE(SUM(CASE WHEN answer_ms > 0 THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN COALESCE(fas, '') != '' THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(fas_ms), 0) / 1000.0,
  COALESCE(AVG(CASE WHEN ring_ms > 0 THEN ring_ms END), 0),
  COALESCE(SUM(CASE WHEN answer_ms > 0 AND end_ms > answer_ms THEN end_ms - answer_ms ELSE 0 END), 0) / 1000.0,
  COALESCE(MAX(CASE WHEN COALESCE(fas, '') != '' THEN started_unix END), 0)
FROM media_calls WHERE started_unix >= ? AND started_unix < ?
GROUP BY 1 ORDER BY 4 DESC, 2 DESC`, from.UnixMilli(), to.UnixMilli())
	if err != nil {
		return nil, err
	}
	var out []RouteStat
	for rows.Next() {
		var r RouteStat
		var avgRing float64
		var last int64
		if err := rows.Scan(&r.Route, &r.Calls, &r.Answered, &r.FAS, &r.FASSeconds, &avgRing, &r.TalkSec, &last); err != nil {
			rows.Close()
			return nil, err
		}
		r.AvgRingMS = int(avgRing)
		if last > 0 {
			r.LastFAS = time.UnixMilli(last).UTC()
		}
		r.ByKind = []KindN{}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	kinds, err := s.db.QueryContext(ctx, `SELECT COALESCE(route, ''), fas, COUNT(*) FROM media_calls
WHERE started_unix >= ? AND started_unix < ? AND COALESCE(fas, '') != '' GROUP BY 1, 2`, from.UnixMilli(), to.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer kinds.Close()
	byRoute := map[string][]KindN{}
	for kinds.Next() {
		var route, kind string
		var n int
		if err := kinds.Scan(&route, &kind, &n); err != nil {
			return nil, err
		}
		byRoute[route] = append(byRoute[route], KindN{Kind: kind, Count: n})
	}
	for i := range out {
		k := byRoute[out[i].Route]
		sort.Slice(k, func(a, b int) bool { return k[a].Count > k[b].Count })
		if k != nil {
			out[i].ByKind = k
		}
	}
	if out == nil {
		out = []RouteStat{}
	}
	return out, kinds.Err()
}

// ExpiredRecordings lists bridged calls whose recording is older than before.
func (s *SQLite) ExpiredRecordings(ctx context.Context, before time.Time, limit int) ([]MediaCall, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+mediaColumns+` FROM media_calls
WHERE COALESCE(recording, '') != '' AND started_unix < ? ORDER BY id ASC LIMIT ?`, before.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MediaCall
	for rows.Next() {
		m, err := scanMedia(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ClearRecording forgets a recording path once the file is gone.
func (s *SQLite) ClearRecording(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE media_calls SET recording = '' WHERE id = ?`, id)
	return err
}

// Routes lists vendor routes, longest prefix first.
func (s *SQLite) Routes(ctx context.Context) ([]Route, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, prefix, label, strip, COALESCE(target, ''), carry, created_at FROM routes ORDER BY LENGTH(prefix) DESC, prefix`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Route{}
	for rows.Next() {
		var r Route
		var strip int
		var created string
		if err := rows.Scan(&r.ID, &r.Prefix, &r.Label, &strip, &r.Target, &r.Carry, &created); err != nil {
			return nil, err
		}
		r.Strip = strip == 1
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// PutRoute creates or replaces the route for a prefix.
func (s *SQLite) PutRoute(ctx context.Context, r Route) (Route, error) {
	r.Prefix = strings.TrimSpace(r.Prefix)
	r.Label = strings.TrimSpace(r.Label)
	r.Target = strings.TrimSpace(r.Target)
	if r.Prefix == "" || r.Label == "" {
		return r, errors.New("prefix and label are required")
	}
	for _, c := range r.Prefix {
		if (c < '0' || c > '9') && c != '#' && c != '*' && c != '+' {
			return r, fmt.Errorf("prefix may hold digits, +, *, and # only")
		}
	}
	if len(r.Prefix) > 16 || len(r.Label) > 64 || len(r.Target) > 128 {
		return r, errors.New("prefix, label, or target is too long")
	}
	switch r.Carry {
	case "":
		r.Carry = CarryAll
	case CarryAll, CarrySuspicious:
	default:
		return r, errors.New("carry must be all or suspicious")
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO routes (prefix, label, strip, target, carry, created_at) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(prefix) DO UPDATE SET label = excluded.label, strip = excluded.strip, target = excluded.target, carry = excluded.carry`,
		r.Prefix, r.Label, boolInt(r.Strip), r.Target, r.Carry, r.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return r, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT id FROM routes WHERE prefix = ?`, r.Prefix).Scan(&r.ID)
	return r, err
}

// DeleteRoute removes a route.
func (s *SQLite) DeleteRoute(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM routes WHERE id = ?`, id)
	return err
}

// Latency reads the time Falcon held INVITEs. Rows from before the
// latency column existed carry 0 and are skipped.
func (s *SQLite) Latency(ctx context.Context, from, to time.Time) (LatencyStats, error) {
	var st LatencyStats
	f, t := from.UTC().Unix(), to.UTC().Unix()
	var avg float64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(AVG(latency_us), 0) FROM events
WHERE received_unix >= ? AND received_unix < ? AND latency_us > 0`, f, t).Scan(&st.Count, &avg); err != nil {
		return st, err
	}
	st.AvgMS = avg / 1000
	if st.Count == 0 {
		return st, nil
	}
	at := func(q float64) (float64, error) {
		off := int(float64(st.Count-1) * q)
		var us int64
		err := s.db.QueryRowContext(ctx, `SELECT latency_us FROM events
WHERE received_unix >= ? AND received_unix < ? AND latency_us > 0 ORDER BY latency_us LIMIT 1 OFFSET ?`, f, t, off).Scan(&us)
		return float64(us) / 1000, err
	}
	var err error
	if st.P50MS, err = at(0.50); err != nil {
		return st, err
	}
	st.P95MS, err = at(0.95)
	return st, err
}
