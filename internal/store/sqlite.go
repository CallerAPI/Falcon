package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/score"

	_ "modernc.org/sqlite"
)

// SQLite is the one store. One file, WAL mode, one writer.
type SQLite struct {
	db *sql.DB
}

func OpenSQLite(path string) (*SQLite, error) {
	s := &SQLite{}
	if err := s.open(path); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLite) open(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	s.db = db
	if err := s.migrate(); err != nil {
		_ = db.Close()
		s.db = nil
		return err
	}
	return nil
}

// Checkpoint flushes WAL so a copy of the file is complete.
func (s *SQLite) Checkpoint() error {
	if s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// ReplaceFile closes the current file, copies src onto dest, and opens dest.
func (s *SQLite) ReplaceFile(src, dest string) error {
	if s.db != nil {
		_ = s.Checkpoint()
		if err := s.db.Close(); err != nil {
			return err
		}
		s.db = nil
	}
	for _, p := range []string{dest, dest + "-wal", dest + "-shm"} {
		_ = os.Remove(p)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return s.open(dest)
}

const eventColumns = `id, received_at, action, risk_score, source_ip, from_num, to_num, call_id, user_agent, attest,
  reasons, %s, switch, exported, COALESCE(provider, ''), COALESCE(verstat, ''), COALESCE(signer_spc, ''),
  COALESCE(signer_name, ''), COALESCE(shaken, ''), COALESCE(fingerprint, ''), COALESCE(direction, ''), COALESCE(customer, ''),
  answered, duration_s, COALESCE(hangup_cause, ''), COALESCE(honeypot, 0), COALESCE(sampled, 0)`

func selectEvents(withRaw bool) string {
	raw := "''"
	if withRaw {
		raw = "raw_sip"
	}
	return "SELECT " + fmt.Sprintf(eventColumns, raw) + " FROM events"
}

func (s *SQLite) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at TEXT NOT NULL,
  action TEXT NOT NULL,
  risk_score INTEGER NOT NULL,
  source_ip TEXT,
  from_num TEXT,
  to_num TEXT,
  call_id TEXT,
  user_agent TEXT,
  attest TEXT,
  reasons TEXT,
  raw_sip TEXT,
  switch TEXT,
  exported INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_received_at ON events(received_at DESC);
CREATE INDEX IF NOT EXISTS events_action ON events(action, received_at DESC);
CREATE INDEX IF NOT EXISTS events_exported ON events(exported, id);
CREATE TABLE IF NOT EXISTS kv (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  subject TEXT NOT NULL,
  value TEXT NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  UNIQUE(kind, subject, value)
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at_unix INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  subject TEXT NOT NULL,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS audit_at ON audit(at_unix DESC);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at_unix INTEGER NOT NULL,
  key TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT,
  delivered INTEGER NOT NULL DEFAULT 0,
  error TEXT
);
CREATE INDEX IF NOT EXISTS alerts_at ON alerts(at_unix DESC);
CREATE INDEX IF NOT EXISTS alerts_key ON alerts(key, at_unix DESC);
CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,
  name TEXT,
  dids TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS voice_samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL,
  call_id TEXT NOT NULL,
  at_unix INTEGER NOT NULL,
  seconds REAL NOT NULL DEFAULT 0,
  channels INTEGER NOT NULL DEFAULT 1,
  phash TEXT,
  caller_speech REAL NOT NULL DEFAULT 0,
  callee_speech REAL NOT NULL DEFAULT 0,
  repeat_count INTEGER NOT NULL DEFAULT 0,
  transcript TEXT,
  category TEXT,
  score REAL NOT NULL DEFAULT 0,
  summary TEXT,
  provider TEXT,
  error TEXT,
  customer TEXT,
  from_num TEXT
);
CREATE INDEX IF NOT EXISTS voice_samples_at ON voice_samples(at_unix DESC);
CREATE INDEX IF NOT EXISTS voice_samples_event ON voice_samples(event_id);
`)
	if err != nil {
		return err
	}
	for _, col := range []struct{ name, typ string }{
		{"provider", "TEXT"},
		{"verstat", "TEXT"},
		{"signer_spc", "TEXT"},
		{"signer_name", "TEXT"},
		{"shaken", "TEXT"},
		{"received_unix", "INTEGER"},
		{"fingerprint", "TEXT"},
		{"direction", "TEXT"},
		{"customer", "TEXT"},
		{"answered", "INTEGER"},
		{"duration_s", "INTEGER"},
		{"hangup_cause", "TEXT"},
		{"ended_unix", "INTEGER"},
		{"honeypot", "INTEGER NOT NULL DEFAULT 0"},
		{"sampled", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := s.addColumnIfMissing("events", col.name, col.typ); err != nil {
			return err
		}
	}
	// Older rows get a unix time from the ISO text once.
	if _, err := s.db.Exec(`UPDATE events SET received_unix = CAST(strftime('%s', substr(received_at, 1, 19)) AS INTEGER) WHERE received_unix IS NULL`); err != nil {
		return err
	}
	_, err = s.db.Exec(`
CREATE INDEX IF NOT EXISTS events_received_unix ON events(received_unix DESC);
CREATE INDEX IF NOT EXISTS events_signer ON events(signer_spc, received_unix DESC);
CREATE INDEX IF NOT EXISTS events_provider ON events(provider, received_unix DESC);
CREATE INDEX IF NOT EXISTS events_source_ip ON events(source_ip, received_unix DESC);
CREATE INDEX IF NOT EXISTS events_fingerprint ON events(fingerprint, received_unix DESC);
CREATE INDEX IF NOT EXISTS events_from_recent ON events(from_num, received_unix DESC);
CREATE INDEX IF NOT EXISTS events_customer ON events(customer, received_unix DESC);
CREATE INDEX IF NOT EXISTS events_call_id ON events(call_id);`)
	return err
}

// addColumnIfMissing is the whole migration story: existing installs keep
// their database and gain columns on first start.
func (s *SQLite) addColumnIfMissing(table, column, typ string) error {
	rows, err := s.db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, typ))
	return err
}

func (s *SQLite) Insert(ctx context.Context, ev Event) (int64, error) {
	if ev.ReceivedAt.IsZero() {
		ev.ReceivedAt = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO events (received_at, received_unix, action, risk_score, source_ip, from_num, to_num, call_id, user_agent, attest,
  reasons, raw_sip, switch, exported, provider, verstat, signer_spc, signer_name, shaken, fingerprint, direction, customer, honeypot, sampled)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ReceivedAt.UTC().Format(time.RFC3339Nano),
		ev.ReceivedAt.UTC().Unix(),
		string(ev.Action),
		ev.RiskScore,
		ev.SourceIP,
		ev.From,
		ev.To,
		ev.CallID,
		ev.UserAgent,
		ev.Attest,
		ReasonsJSON(ev.Reasons),
		ev.RawSIP,
		ev.Switch,
		ev.Provider,
		ev.Verstat,
		ev.SignerSPC,
		ev.SignerName,
		string(ev.Shaken),
		ev.Fingerprint,
		ev.Direction,
		ev.Customer,
		boolInt(ev.Honeypot),
		boolInt(ev.Sampled),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *SQLite) Recent(ctx context.Context, limit int) ([]Event, error) {
	return s.Query(ctx, Filter{Limit: limit})
}

func (s *SQLite) Query(ctx context.Context, f Filter) ([]Event, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	where, args := whereFor(f)
	if f.BeforeID > 0 {
		where = append(where, "id < ?")
		args = append(args, f.BeforeID)
	}
	q := selectEvents(false)
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func whereFor(f Filter) ([]string, []any) {
	var where []string
	var args []any
	if !f.From.IsZero() {
		where = append(where, "received_unix >= ?")
		args = append(args, f.From.UTC().Unix())
	}
	if !f.To.IsZero() {
		where = append(where, "received_unix < ?")
		args = append(args, f.To.UTC().Unix())
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}
	if f.Verstat != "" {
		where = append(where, "verstat = ?")
		args = append(args, f.Verstat)
	}
	if f.IP != "" {
		where = append(where, "source_ip = ?")
		args = append(args, f.IP)
	}
	if f.SPC != "" {
		where = append(where, "signer_spc = ?")
		args = append(args, f.SPC)
	}
	if f.Provider != "" {
		where = append(where, "provider = ?")
		args = append(args, f.Provider)
	}
	if f.Fingerprint != "" {
		where = append(where, "fingerprint = ?")
		args = append(args, f.Fingerprint)
	}
	if f.Direction != "" {
		where = append(where, "direction = ?")
		args = append(args, f.Direction)
	}
	if f.Customer != "" {
		where = append(where, "customer = ?")
		args = append(args, f.Customer)
	}
	if f.Number != "" {
		where = append(where, "(from_num = ? OR to_num = ?)")
		args = append(args, f.Number, f.Number)
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		like := "%" + q + "%"
		where = append(where, "(from_num LIKE ? OR to_num LIKE ? OR source_ip LIKE ? OR call_id LIKE ? OR user_agent LIKE ? OR provider LIKE ? OR signer_spc LIKE ? OR signer_name LIKE ? OR reasons LIKE ? OR fingerprint LIKE ?)")
		for i := 0; i < 10; i++ {
			args = append(args, like)
		}
	}
	return where, args
}

func (s *SQLite) Get(ctx context.Context, id int64) (Event, error) {
	row := s.db.QueryRowContext(ctx, selectEvents(true)+` WHERE id = ?`, id)
	return scanEvent(row)
}

func (s *SQLite) Stats(ctx context.Context, from, to time.Time) (Stats, error) {
	st := Stats{ByAction: map[string]int{}, ByVerstat: map[string]int{}, ByAttest: map[string]int{}}
	f, t := from.UTC().Unix(), to.UTC().Unix()
	row := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(AVG(risk_score), 0) FROM events WHERE received_unix >= ? AND received_unix < ?`, f, t)
	if err := row.Scan(&st.Total, &st.AvgScore); err != nil {
		return st, err
	}
	for _, g := range []struct {
		col  string
		into map[string]int
	}{{"action", st.ByAction}, {"verstat", st.ByVerstat}, {"attest", st.ByAttest}} {
		rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`SELECT COALESCE(%s, ''), COUNT(*) FROM events WHERE received_unix >= ? AND received_unix < ? GROUP BY 1`, g.col), f, t)
		if err != nil {
			return st, err
		}
		for rows.Next() {
			var k string
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				rows.Close()
				return st, err
			}
			if k == "" {
				k = "none"
			}
			g.into[k] = n
		}
		rows.Close()
	}
	var err error
	if st.TopIPs, err = s.top(ctx, "source_ip", from, to, 8); err != nil {
		return st, err
	}
	if st.TopUAs, err = s.top(ctx, "user_agent", from, to, 8); err != nil {
		return st, err
	}
	if st.TopProviders, err = s.top(ctx, "provider", from, to, 8); err != nil {
		return st, err
	}
	if st.TopSigners, err = s.top(ctx, "signer_spc", from, to, 8); err != nil {
		return st, err
	}
	if st.TopReasons, err = s.topReasons(ctx, from, to, 10); err != nil {
		return st, err
	}
	step := StepFor(from, to)
	st.StepSeconds = int(step.Seconds())
	st.Timeseries, err = s.timeseries(ctx, from, to, step)
	// Empty lists serialise as [] so clients never branch on null.
	for _, p := range []*[]NameCount{&st.TopIPs, &st.TopUAs, &st.TopProviders, &st.TopSigners, &st.TopReasons} {
		if *p == nil {
			*p = []NameCount{}
		}
	}
	if st.Timeseries == nil {
		st.Timeseries = []Bucket{}
	}
	return st, err
}

func (s *SQLite) timeseries(ctx context.Context, from, to time.Time, step time.Duration) ([]Bucket, error) {
	sec := int64(step.Seconds())
	rows, err := s.db.QueryContext(ctx, `
SELECT (received_unix / ?) * ? AS b,
  COUNT(*),
  SUM(CASE WHEN action = 'allow' THEN 1 ELSE 0 END),
  SUM(CASE WHEN action = 'flag' THEN 1 ELSE 0 END),
  SUM(CASE WHEN action = 'challenge' THEN 1 ELSE 0 END),
  SUM(CASE WHEN action = 'reject' THEN 1 ELSE 0 END),
  AVG(risk_score)
FROM events WHERE received_unix >= ? AND received_unix < ?
GROUP BY b ORDER BY b`, sec, sec, from.UTC().Unix(), to.UTC().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	got := map[int64]Bucket{}
	for rows.Next() {
		var b int64
		var bk Bucket
		if err := rows.Scan(&b, &bk.Count, &bk.Allow, &bk.Flag, &bk.Challenge, &bk.Reject, &bk.Avg); err != nil {
			return nil, err
		}
		bk.TS = time.Unix(b, 0).UTC()
		got[b] = bk
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Dense series: every bucket in the window, zeros where nothing came in.
	var out []Bucket
	start := (from.UTC().Unix() / sec) * sec
	end := to.UTC().Unix()
	for b := start; b < end && len(out) < 2000; b += sec {
		if bk, ok := got[b]; ok {
			out = append(out, bk)
		} else {
			out = append(out, Bucket{TS: time.Unix(b, 0).UTC()})
		}
	}
	return out, nil
}

func (s *SQLite) top(ctx context.Context, col string, from, to time.Time, limit int) ([]NameCount, error) {
	switch col {
	case "source_ip", "user_agent", "provider", "signer_spc":
	default:
		return nil, fmt.Errorf("unsupported column")
	}
	q := fmt.Sprintf(`SELECT COALESCE(%s, '') AS name, COUNT(*) AS c FROM events
WHERE received_unix >= ? AND received_unix < ? AND COALESCE(%s, '') != ''
GROUP BY name ORDER BY c DESC LIMIT ?`, col, col)
	rows, err := s.db.QueryContext(ctx, q, from.UTC().Unix(), to.UTC().Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NameCount
	for rows.Next() {
		var nc NameCount
		if err := rows.Scan(&nc.Name, &nc.Count); err != nil {
			return nil, err
		}
		out = append(out, nc)
	}
	return out, rows.Err()
}

// topReasons counts reason codes from the JSON column. It reads at most a
// few thousand recent rows in the window, which is enough for a ranking.
func (s *SQLite) topReasons(ctx context.Context, from, to time.Time, limit int) ([]NameCount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT reasons FROM events WHERE received_unix >= ? AND received_unix < ? AND action != 'allow' ORDER BY id DESC LIMIT 5000`, from.UTC().Unix(), to.UTC().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int{}
	weights := map[string]int{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		for _, r := range ParseReasons(raw) {
			counts[r.Code]++
			weights[r.Code] += r.Weight
		}
	}
	out := make([]NameCount, 0, len(counts))
	for k, v := range counts {
		out = append(out, NameCount{Name: k, Count: v})
	}
	// Most frequent first. Equal counts rank by the weight they carried, so
	// the reasons that decide calls sit above the ones that only colour them.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if weights[out[i].Name] != weights[out[j].Name] {
			return weights[out[i].Name] > weights[out[j].Name]
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, rows.Err()
}

// Histogram returns ten buckets of risk score: 0-9, 10-19, ... 90-100.
func (s *SQLite) Histogram(ctx context.Context, from, to time.Time) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT MIN(risk_score / 10, 9), COUNT(*) FROM events WHERE received_unix >= ? AND received_unix < ? GROUP BY 1`, from.UTC().Unix(), to.UTC().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]int, 10)
	for rows.Next() {
		var b, n int
		if err := rows.Scan(&b, &n); err != nil {
			return nil, err
		}
		if b >= 0 && b < 10 {
			out[b] = n
		}
	}
	return out, rows.Err()
}

// Parties aggregates by "provider", "signer", or "ip".
func (s *SQLite) Parties(ctx context.Context, by string, from, to time.Time, limit int) ([]Party, error) {
	var col, label string
	switch by {
	case "provider":
		col, label = "provider", "''"
	case "signer":
		col, label = "signer_spc", "MAX(COALESCE(signer_name, ''))"
	case "ip":
		col, label = "source_ip", "MAX(COALESCE(provider, ''))"
	case "fingerprint":
		col, label = "fingerprint", "MAX(COALESCE(user_agent, ''))"
	case "customer":
		col, label = "customer", "''"
	case "caller":
		col, label = "from_num", "MAX(COALESCE(signer_name, ''))"
	default:
		return nil, fmt.Errorf("unsupported grouping %q", by)
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := fmt.Sprintf(`
SELECT COALESCE(%s, ''), %s, COUNT(*),
  SUM(CASE WHEN action = 'reject' THEN 1 ELSE 0 END),
  SUM(CASE WHEN action = 'flag' OR action = 'challenge' THEN 1 ELSE 0 END),
  AVG(risk_score),
  SUM(CASE WHEN attest = 'A' THEN 1 ELSE 0 END),
  SUM(CASE WHEN attest = 'B' THEN 1 ELSE 0 END),
  SUM(CASE WHEN attest = 'C' THEN 1 ELSE 0 END),
  SUM(CASE WHEN verstat = 'TN-Validation-Passed' THEN 1 ELSE 0 END),
  SUM(CASE WHEN verstat = 'TN-Validation-Failed' THEN 1 ELSE 0 END),
  COUNT(DISTINCT from_num),
  MIN(received_unix), MAX(received_unix)
FROM events
WHERE received_unix >= ? AND received_unix < ? AND COALESCE(%s, '') != ''
GROUP BY 1 ORDER BY 3 DESC LIMIT ?`, col, label, col)
	rows, err := s.db.QueryContext(ctx, q, from.UTC().Unix(), to.UTC().Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Party
	for rows.Next() {
		var p Party
		var first, last int64
		if err := rows.Scan(&p.Name, &p.Label, &p.Total, &p.Reject, &p.Flag, &p.AvgScore, &p.AttestA, &p.AttestB, &p.AttestC, &p.Passed, &p.Failed, &p.Distinct, &first, &last); err != nil {
			return nil, err
		}
		p.FirstSeen = time.Unix(first, 0).UTC()
		p.LastSeen = time.Unix(last, 0).UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLite) Unexported(ctx context.Context, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, selectEvents(true)+` WHERE exported = 0 ORDER BY id ASC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (s *SQLite) MarkExported(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	args := make([]any, len(ids))
	ph := make([]string, len(ids))
	for i, id := range ids {
		args[i] = id
		ph[i] = "?"
	}
	_, err := s.db.ExecContext(ctx, `UPDATE events SET exported = 1 WHERE id IN (`+strings.Join(ph, ",")+`)`, args...)
	return err
}

// Prune deletes events older than before and returns the count.
func (s *SQLite) Prune(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE received_unix < ?`, before.UTC().Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ScrubRawSIP blanks the raw message on events older than before. The
// decision, the score, and the reasons stay. Raw SIP carries subscriber
// numbers in the clear and should not outlive its use.
func (s *SQLite) ScrubRawSIP(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE events SET raw_sip = '' WHERE received_unix < ? AND raw_sip IS NOT NULL AND raw_sip != ''`, before.UTC().Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *SQLite) Rules(ctx context.Context) ([]lists.Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, subject, value, COALESCE(note, ''), created_at, COALESCE(expires_at, '') FROM rules ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []lists.Rule
	for rows.Next() {
		var r lists.Rule
		var kind, subject, created, expires string
		if err := rows.Scan(&r.ID, &kind, &subject, &r.Value, &r.Note, &created, &expires); err != nil {
			return nil, err
		}
		r.Kind, r.Subject = lists.Kind(kind), lists.Subject(subject)
		r.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if expires != "" {
			r.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLite) AddRule(ctx context.Context, r lists.Rule) (lists.Rule, error) {
	r, err := lists.Normalize(r)
	if err != nil {
		return r, err
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	var expires any
	if !r.ExpiresAt.IsZero() {
		expires = r.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO rules (kind, subject, value, note, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(kind, subject, value) DO UPDATE SET note = excluded.note, expires_at = excluded.expires_at`,
		string(r.Kind), string(r.Subject), r.Value, r.Note, r.CreatedAt.UTC().Format(time.RFC3339Nano), expires)
	if err != nil {
		return r, err
	}
	if id, err := res.LastInsertId(); err == nil && id > 0 {
		r.ID = id
	}
	if r.ID == 0 {
		_ = s.db.QueryRowContext(ctx, `SELECT id FROM rules WHERE kind = ? AND subject = ? AND value = ?`, string(r.Kind), string(r.Subject), r.Value).Scan(&r.ID)
	}
	return r, nil
}

func (s *SQLite) DeleteRule(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id = ?`, id)
	return err
}

func (s *SQLite) KVGet(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT v FROM kv WHERE k = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *SQLite) KVSet(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO kv(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, key, value)
	return err
}

func (s *SQLite) Close() error {
	return s.db.Close()
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	var out []Event
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEvent(row rowScanner) (Event, error) {
	var ev Event
	var received, action, reasons, raw, shaken string
	var exported, honeypot, sampled int
	var answered, duration sql.NullInt64
	err := row.Scan(
		&ev.ID, &received, &action, &ev.RiskScore, &ev.SourceIP, &ev.From, &ev.To,
		&ev.CallID, &ev.UserAgent, &ev.Attest, &reasons, &raw, &ev.Switch, &exported,
		&ev.Provider, &ev.Verstat, &ev.SignerSPC, &ev.SignerName, &shaken, &ev.Fingerprint, &ev.Direction, &ev.Customer,
		&answered, &duration, &ev.HangupCause, &honeypot, &sampled,
	)
	if err != nil {
		return ev, err
	}
	if answered.Valid {
		b := answered.Int64 == 1
		ev.Answered = &b
	}
	if duration.Valid {
		d := int(duration.Int64)
		ev.DurationS = &d
	}
	ev.Honeypot = honeypot == 1
	ev.Sampled = sampled == 1
	if t, err := time.Parse(time.RFC3339Nano, received); err == nil {
		ev.ReceivedAt = t
	} else if t, err := time.Parse(time.RFC3339, received); err == nil {
		ev.ReceivedAt = t
	}
	ev.Action = scoreAction(action)
	ev.Reasons = ParseReasons(reasons)
	ev.RawSIP = raw
	if strings.HasPrefix(strings.TrimSpace(shaken), "{") {
		ev.Shaken = json.RawMessage(shaken)
	}
	ev.Exported = exported == 1
	return ev, nil
}

func scoreAction(s string) score.Action {
	switch s {
	case "reject":
		return score.ActionReject
	case "challenge":
		return score.ActionChallenge
	case "flag":
		return score.ActionFlag
	default:
		return score.ActionAllow
	}
}

// Audit appends one entry. Failures are logged by the caller, never fatal.
func (s *SQLite) Audit(ctx context.Context, e AuditEntry) error {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit (at_unix, actor, action, subject, detail) VALUES (?, ?, ?, ?, ?)`,
		e.At.Unix(), e.Actor, e.Action, e.Subject, e.Detail)
	return err
}

// AuditLog returns the newest entries.
func (s *SQLite) AuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, at_unix, actor, action, subject, COALESCE(detail, '') FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Subject, &e.Detail); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddAlert stores a fired alert.
func (s *SQLite) AddAlert(ctx context.Context, a Alert) (int64, error) {
	if a.At.IsZero() {
		a.At = time.Now().UTC()
	}
	delivered := 0
	if a.Delivered {
		delivered = 1
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO alerts (at_unix, key, severity, title, detail, delivered, error) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.At.Unix(), a.Key, a.Severity, a.Title, a.Detail, delivered, a.Error)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Alerts returns the newest alerts.
func (s *SQLite) Alerts(ctx context.Context, limit int) ([]Alert, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, at_unix, key, severity, title, COALESCE(detail, ''), delivered, COALESCE(error, '') FROM alerts ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		var at int64
		var delivered int
		if err := rows.Scan(&a.ID, &at, &a.Key, &a.Severity, &a.Title, &a.Detail, &delivered, &a.Error); err != nil {
			return nil, err
		}
		a.At = time.Unix(at, 0).UTC()
		a.Delivered = delivered == 1
		out = append(out, a)
	}
	return out, rows.Err()
}

// LastAlert is when a key last fired, for cooldowns.
func (s *SQLite) LastAlert(ctx context.Context, key string) (time.Time, bool, error) {
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT at_unix FROM alerts WHERE key = ? ORDER BY id DESC LIMIT 1`, key).Scan(&at)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return time.Unix(at, 0).UTC(), true, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
