package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/lists"
)

// Upstream is a carrier that sends this operator calls. The operator names
// its addresses and signer codes, and its RMD number or FRN so the FCC
// autopilot can check it. Standing is the last result of that check.
type Upstream struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	RMD           string     `json:"rmd,omitempty"`
	FRN           string     `json:"frn,omitempty"`
	IPs           []string   `json:"ips"`
	SPCs          []string   `json:"spcs"`
	Contact       string     `json:"contact,omitempty"`
	Note          string     `json:"note,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	Standing      string     `json:"standing,omitempty"`
	StandingSince *time.Time `json:"standing_since,omitempty"`
}

// ComplianceEntry is one line of the FCC autopilot log: a change of
// standing, a block, or a release.
type ComplianceEntry struct {
	ID         int64     `json:"id"`
	At         time.Time `json:"at"`
	UpstreamID int64     `json:"upstream_id"`
	Upstream   string    `json:"upstream"`
	Standing   string    `json:"standing"`
	Provider   string    `json:"provider,omitempty"`
	Doc        string    `json:"doc,omitempty"`
	Action     string    `json:"action"`
	Detail     string    `json:"detail,omitempty"`
}

// ComplianceStore keeps the upstream registry and the autopilot log.
type ComplianceStore interface {
	Upstreams(ctx context.Context) ([]Upstream, error)
	Upstream(ctx context.Context, id int64) (Upstream, bool, error)
	PutUpstream(ctx context.Context, u Upstream) (Upstream, error)
	DeleteUpstream(ctx context.Context, id int64) error
	SetUpstreamStanding(ctx context.Context, id int64, standing string, since time.Time) error
	ReplaceOriginRules(ctx context.Context, origin string, rules []lists.Rule) error
	AddComplianceEntry(ctx context.Context, e ComplianceEntry) (int64, error)
	ComplianceLog(ctx context.Context, limit int) ([]ComplianceEntry, error)
}

func (s *SQLite) migrateCompliance() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS upstreams (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  rmd TEXT NOT NULL DEFAULT '',
  frn TEXT NOT NULL DEFAULT '',
  ips TEXT NOT NULL DEFAULT '',
  spcs TEXT NOT NULL DEFAULT '',
  contact TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  standing TEXT NOT NULL DEFAULT '',
  standing_since TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS compliance_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at_unix INTEGER NOT NULL,
  upstream_id INTEGER NOT NULL,
  upstream TEXT NOT NULL,
  standing TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT '',
  doc TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS compliance_log_at ON compliance_log(at_unix DESC);`)
	return err
}

const upstreamColumns = `id, name, rmd, frn, ips, spcs, contact, note, created_at, standing, standing_since`

func scanUpstream(row interface{ Scan(...any) error }) (Upstream, error) {
	var u Upstream
	var ips, spcs, created, since string
	if err := row.Scan(&u.ID, &u.Name, &u.RMD, &u.FRN, &ips, &spcs, &u.Contact, &u.Note, &created, &u.Standing, &since); err != nil {
		return u, err
	}
	u.IPs, u.SPCs = splitList(ips), splitList(spcs)
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if t, err := time.Parse(time.RFC3339Nano, since); err == nil {
		u.StandingSince = &t
	}
	return u, nil
}

func splitList(s string) []string {
	out := []string{}
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (s *SQLite) Upstreams(ctx context.Context) ([]Upstream, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+upstreamColumns+` FROM upstreams ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Upstream{}
	for rows.Next() {
		u, err := scanUpstream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *SQLite) Upstream(ctx context.Context, id int64) (Upstream, bool, error) {
	u, err := scanUpstream(s.db.QueryRowContext(ctx, `SELECT `+upstreamColumns+` FROM upstreams WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Upstream{}, false, nil
	}
	return u, err == nil, err
}

// PutUpstream inserts an upstream, or replaces the one with u.ID. Standing
// is left to SetUpstreamStanding.
func (s *SQLite) PutUpstream(ctx context.Context, u Upstream) (Upstream, error) {
	ips, spcs := strings.Join(u.IPs, ","), strings.Join(u.SPCs, ",")
	if u.ID > 0 {
		res, err := s.db.ExecContext(ctx, `UPDATE upstreams SET name = ?, rmd = ?, frn = ?, ips = ?, spcs = ?, contact = ?, note = ? WHERE id = ?`,
			u.Name, u.RMD, u.FRN, ips, spcs, u.Contact, u.Note, u.ID)
		if err != nil {
			return u, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return u, errors.New("no upstream with that id")
		}
		saved, _, err := s.Upstream(ctx, u.ID)
		return saved, err
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO upstreams (name, rmd, frn, ips, spcs, contact, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.Name, u.RMD, u.FRN, ips, spcs, u.Contact, u.Note, u.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return u, err
	}
	u.ID, err = res.LastInsertId()
	return u, err
}

func (s *SQLite) DeleteUpstream(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM upstreams WHERE id = ?`, id)
	return err
}

func (s *SQLite) SetUpstreamStanding(ctx context.Context, id int64, standing string, since time.Time) error {
	at := ""
	if !since.IsZero() {
		at = since.UTC().Format(time.RFC3339Nano)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE upstreams SET standing = ?, standing_since = ? WHERE id = ?`, standing, at, id)
	return err
}

// ReplaceOriginRules swaps every rule of one origin for rules. Rules of
// other origins stay. A value that already has a rule of the same kind keeps
// that rule.
func (s *SQLite) ReplaceOriginRules(ctx context.Context, origin string, rules []lists.Rule) error {
	if origin == "" || origin == "local" {
		return errors.New("local rules are not replaced")
	}
	ready := make([]lists.Rule, 0, len(rules))
	for _, r := range rules {
		n, err := lists.Normalize(r)
		if err != nil {
			return err
		}
		if n.CreatedAt.IsZero() {
			n.CreatedAt = time.Now().UTC()
		}
		ready = append(ready, n)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM rules WHERE origin = ?`, origin); err != nil {
		return err
	}
	for _, r := range ready {
		var expires any
		if !r.ExpiresAt.IsZero() {
			expires = r.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO rules (kind, subject, value, note, created_at, expires_at, origin) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(kind, subject, value) DO NOTHING`,
			string(r.Kind), string(r.Subject), r.Value, r.Note, r.CreatedAt.UTC().Format(time.RFC3339Nano), expires, origin); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLite) AddComplianceEntry(ctx context.Context, e ComplianceEntry) (int64, error) {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO compliance_log (at_unix, upstream_id, upstream, standing, provider, doc, action, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At.Unix(), e.UpstreamID, e.Upstream, e.Standing, e.Provider, e.Doc, e.Action, e.Detail)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *SQLite) ComplianceLog(ctx context.Context, limit int) ([]ComplianceEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, at_unix, upstream_id, upstream, standing, provider, doc, action, detail FROM compliance_log ORDER BY at_unix DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ComplianceEntry{}
	for rows.Next() {
		var e ComplianceEntry
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.UpstreamID, &e.Upstream, &e.Standing, &e.Provider, &e.Doc, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}
