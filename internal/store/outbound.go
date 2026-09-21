package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Outcome is what the switch reports when a call ends. It turns an INVITE
// into a call: answered or not, how long, why it ended.
type Outcome struct {
	Answered    bool   `json:"answered"`
	DurationS   int    `json:"duration_s"`
	HangupCause string `json:"hangup_cause,omitempty"`
}

// Activity summarises one calling number or one customer over a window.
// These are the numbers behind robocall detection everywhere: how many
// calls, to how many different people, how many answered, how long.
type Activity struct {
	Calls           int `json:"calls"`
	DistinctCallees int `json:"distinct_callees"`
	DistinctCallers int `json:"distinct_callers"`
	Completed       int `json:"completed"`
	Answered        int `json:"answered"`
	TalkSeconds     int `json:"talk_seconds"`
	Rejects         int `json:"rejects"`
	HoneypotHits    int `json:"honeypot_hits"`
	// LastCallees are the most recent called numbers, oldest first, for
	// sequential dialing detection.
	LastCallees []string `json:"-"`
}

// ASR is the answer seizure ratio in percent over completed calls.
func (a Activity) ASR() int {
	if a.Completed == 0 {
		return 0
	}
	return a.Answered * 100 / a.Completed
}

// ACD is the average talk time in seconds over answered calls.
func (a Activity) ACD() int {
	if a.Answered == 0 {
		return 0
	}
	return a.TalkSeconds / a.Answered
}

// Sequential reports whether the recent callees look like a dialer walking
// a number range: at least n of the last callees each one more than the
// previous.
func (a Activity) Sequential(n int) bool {
	if n < 2 || len(a.LastCallees) < n {
		return false
	}
	run := 1
	for i := 1; i < len(a.LastCallees); i++ {
		if isNext(a.LastCallees[i-1], a.LastCallees[i]) {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

func isNext(prev, cur string) bool {
	p, c := digitsOnly(prev), digitsOnly(cur)
	if len(p) < 7 || len(p) != len(c) || p[:len(p)-4] != c[:len(c)-4] {
		return false
	}
	var pn, cn int
	for _, r := range p[len(p)-4:] {
		pn = pn*10 + int(r-'0')
	}
	for _, r := range c[len(c)-4:] {
		cn = cn*10 + int(r-'0')
	}
	return cn == pn+1
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Customer is one of the operator's own accounts and the numbers it may
// present. Outbound calls from a customer with a caller id outside its
// list are spoofing.
type Customer struct {
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	DIDs      []string  `json:"dids"`
	CreatedAt time.Time `json:"created_at"`
}

// Owns reports whether the number is in the customer's list. Entries
// ending in * are prefixes.
func (c Customer) Owns(number string) bool {
	n := digitsOnly(number)
	if n == "" {
		return false
	}
	for _, d := range c.DIDs {
		d = strings.TrimSpace(d)
		if strings.HasSuffix(d, "*") {
			if strings.HasPrefix(n, digitsOnly(strings.TrimSuffix(d, "*"))) {
				return true
			}
			continue
		}
		if digitsOnly(d) == n {
			return true
		}
	}
	return false
}

// VoiceSample is one audio clip the switch handed over, with what Falcon
// made of it. The transcript stays here; it is never shared.
type VoiceSample struct {
	ID           int64     `json:"id"`
	EventID      int64     `json:"event_id"`
	CallID       string    `json:"call_id"`
	At           time.Time `json:"at"`
	Seconds      float64   `json:"seconds"`
	Channels     int       `json:"channels"`
	PHash        string    `json:"phash"`
	CallerSpeech float64   `json:"caller_speech"`
	CalleeSpeech float64   `json:"callee_speech"`
	RepeatCount  int       `json:"repeat_count"`
	Transcript   string    `json:"transcript,omitempty"`
	Category     string    `json:"category,omitempty"`
	Score        float64   `json:"score"`
	Summary      string    `json:"summary,omitempty"`
	Provider     string    `json:"provider,omitempty"`
	Error        string    `json:"error,omitempty"`
	Customer     string    `json:"customer,omitempty"`
	From         string    `json:"from,omitempty"`
}

// SetOutcome records how a call ended, by Call-ID. Returns the event.
func (s *SQLite) SetOutcome(ctx context.Context, callID string, o Outcome) (Event, error) {
	answered := 0
	if o.Answered {
		answered = 1
	}
	res, err := s.db.ExecContext(ctx, `UPDATE events SET answered = ?, duration_s = ?, hangup_cause = ?, ended_unix = ?
WHERE id = (SELECT id FROM events WHERE call_id = ? ORDER BY id DESC LIMIT 1)`,
		answered, o.DurationS, o.HangupCause, time.Now().Unix(), callID)
	if err != nil {
		return Event{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Event{}, errors.New("no event with that call id")
	}
	row := s.db.QueryRowContext(ctx, selectEvents(false)+` WHERE call_id = ? ORDER BY id DESC LIMIT 1`, callID)
	return scanEvent(row)
}

// MarkSampled notes that the switch was asked for audio on this event.
func (s *SQLite) MarkSampled(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE events SET sampled = 1 WHERE id = ?`, id)
	return err
}

// CallerActivity summarises one calling number since a time.
func (s *SQLite) CallerActivity(ctx context.Context, from string, since time.Time) (Activity, error) {
	return s.activity(ctx, "from_num", from, since)
}

// CustomerActivity summarises one customer since a time.
func (s *SQLite) CustomerActivity(ctx context.Context, customer string, since time.Time) (Activity, error) {
	return s.activity(ctx, "customer", customer, since)
}

func (s *SQLite) activity(ctx context.Context, col, val string, since time.Time) (Activity, error) {
	var a Activity
	if val == "" {
		return a, nil
	}
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*), COUNT(DISTINCT to_num), COUNT(DISTINCT from_num),
  COUNT(answered), COALESCE(SUM(answered), 0), COALESCE(SUM(CASE WHEN answered = 1 THEN duration_s ELSE 0 END), 0),
  SUM(CASE WHEN action = 'reject' THEN 1 ELSE 0 END), COALESCE(SUM(honeypot), 0)
FROM events WHERE `+col+` = ? AND received_unix >= ?`, val, since.Unix()).Scan(
		&a.Calls, &a.DistinctCallees, &a.DistinctCallers, &a.Completed, &a.Answered, &a.TalkSeconds, &a.Rejects, &a.HoneypotHits)
	if err != nil {
		return a, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT to_num FROM (SELECT id, to_num FROM events WHERE `+col+` = ? AND received_unix >= ? ORDER BY id DESC LIMIT 8) ORDER BY id ASC`, val, since.Unix())
	if err != nil {
		return a, err
	}
	defer rows.Close()
	for rows.Next() {
		var to string
		if err := rows.Scan(&to); err != nil {
			return a, err
		}
		a.LastCallees = append(a.LastCallees, to)
	}
	return a, rows.Err()
}

// WindowActivity summarises every call since a time, for averages.
func (s *SQLite) WindowActivity(ctx context.Context, since time.Time) (Activity, error) {
	var a Activity
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*), COUNT(DISTINCT to_num), COUNT(DISTINCT from_num),
  COUNT(answered), COALESCE(SUM(answered), 0), COALESCE(SUM(CASE WHEN answered = 1 THEN duration_s ELSE 0 END), 0),
  SUM(CASE WHEN action = 'reject' THEN 1 ELSE 0 END), COALESCE(SUM(honeypot), 0)
FROM events WHERE received_unix >= ?`, since.Unix()).Scan(
		&a.Calls, &a.DistinctCallees, &a.DistinctCallers, &a.Completed, &a.Answered, &a.TalkSeconds, &a.Rejects, &a.HoneypotHits)
	return a, err
}

// CountReason counts events in a window whose reasons carry a code.
func (s *SQLite) CountReason(ctx context.Context, from, to time.Time, code string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE received_unix >= ? AND received_unix < ? AND reasons LIKE ?`,
		from.Unix(), to.Unix(), `%"code":"`+code+`"%`).Scan(&n)
	return n, err
}

// Customers lists the operator's accounts.
func (s *SQLite) Customers(ctx context.Context) ([]Customer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, COALESCE(name, ''), dids, created_at FROM customers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Customer{}
	for rows.Next() {
		var c Customer
		var dids, created string
		if err := rows.Scan(&c.ID, &c.Name, &dids, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(dids), &c.DIDs)
		if c.DIDs == nil {
			c.DIDs = []string{}
		}
		c.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, c)
	}
	return out, rows.Err()
}

// Customer returns one account.
func (s *SQLite) Customer(ctx context.Context, id string) (Customer, bool, error) {
	var c Customer
	var dids, created string
	err := s.db.QueryRowContext(ctx, `SELECT id, COALESCE(name, ''), dids, created_at FROM customers WHERE id = ?`, id).Scan(&c.ID, &c.Name, &dids, &created)
	if err == sql.ErrNoRows {
		return c, false, nil
	}
	if err != nil {
		return c, false, err
	}
	_ = json.Unmarshal([]byte(dids), &c.DIDs)
	c.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return c, true, nil
}

// PutCustomer creates or replaces an account.
func (s *SQLite) PutCustomer(ctx context.Context, c Customer) error {
	if strings.TrimSpace(c.ID) == "" {
		return errors.New("customer id required")
	}
	if c.DIDs == nil {
		c.DIDs = []string{}
	}
	dids, _ := json.Marshal(c.DIDs)
	_, err := s.db.ExecContext(ctx, `INSERT INTO customers (id, name, dids, created_at) VALUES (?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET name = excluded.name, dids = excluded.dids`, c.ID, c.Name, string(dids), time.Now().UTC().Format(time.RFC3339))
	return err
}

// DeleteCustomer removes an account.
func (s *SQLite) DeleteCustomer(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM customers WHERE id = ?`, id)
	return err
}

// AddVoiceSample stores a clip's analysis.
func (s *SQLite) AddVoiceSample(ctx context.Context, v VoiceSample) (int64, error) {
	if v.At.IsZero() {
		v.At = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO voice_samples
 (event_id, call_id, at_unix, seconds, channels, phash, caller_speech, callee_speech, repeat_count, transcript, category, score, summary, provider, error, customer, from_num)
 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.EventID, v.CallID, v.At.Unix(), v.Seconds, v.Channels, v.PHash, v.CallerSpeech, v.CalleeSpeech, v.RepeatCount,
		v.Transcript, v.Category, v.Score, v.Summary, v.Provider, v.Error, v.Customer, v.From)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateVoiceSample writes the provider's result onto a stored clip.
func (s *SQLite) UpdateVoiceSample(ctx context.Context, v VoiceSample) error {
	_, err := s.db.ExecContext(ctx, `UPDATE voice_samples SET transcript = ?, category = ?, score = ?, summary = ?, provider = ?, error = ?, seconds = ? WHERE id = ?`,
		v.Transcript, v.Category, v.Score, v.Summary, v.Provider, v.Error, v.Seconds, v.ID)
	return err
}

const voiceColumns = `id, event_id, call_id, at_unix, seconds, channels, COALESCE(phash, ''), caller_speech, callee_speech, repeat_count,
 COALESCE(transcript, ''), COALESCE(category, ''), score, COALESCE(summary, ''), COALESCE(provider, ''), COALESCE(error, ''), COALESCE(customer, ''), COALESCE(from_num, '')`

func scanVoice(row rowScanner) (VoiceSample, error) {
	var v VoiceSample
	var at int64
	err := row.Scan(&v.ID, &v.EventID, &v.CallID, &at, &v.Seconds, &v.Channels, &v.PHash, &v.CallerSpeech, &v.CalleeSpeech, &v.RepeatCount,
		&v.Transcript, &v.Category, &v.Score, &v.Summary, &v.Provider, &v.Error, &v.Customer, &v.From)
	v.At = time.Unix(at, 0).UTC()
	return v, err
}

// VoiceSamples lists the newest clips.
func (s *SQLite) VoiceSamples(ctx context.Context, limit int) ([]VoiceSample, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+voiceColumns+` FROM voice_samples ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VoiceSample{}
	for rows.Next() {
		v, err := scanVoice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// VoiceSampleByCallID returns the newest sample for a Call-ID. Live
// sessions update one row across their webhook events.
func (s *SQLite) VoiceSampleByCallID(ctx context.Context, callID string) (VoiceSample, bool, error) {
	v, err := scanVoice(s.db.QueryRowContext(ctx, `SELECT `+voiceColumns+` FROM voice_samples WHERE call_id = ? ORDER BY id DESC LIMIT 1`, callID))
	if err == sql.ErrNoRows {
		return v, false, nil
	}
	return v, err == nil, err
}

// VoiceSampleForEvent returns the clip attached to an event.
func (s *SQLite) VoiceSampleForEvent(ctx context.Context, eventID int64) (VoiceSample, bool, error) {
	v, err := scanVoice(s.db.QueryRowContext(ctx, `SELECT `+voiceColumns+` FROM voice_samples WHERE event_id = ? ORDER BY id DESC LIMIT 1`, eventID))
	if err == sql.ErrNoRows {
		return v, false, nil
	}
	return v, err == nil, err
}

// RecentPHashes returns perceptual hashes of clips since a time, for
// repeat-recording detection.
func (s *SQLite) RecentPHashes(ctx context.Context, since time.Time, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 2000
	}
	rows, err := s.db.QueryContext(ctx, `SELECT phash FROM voice_samples WHERE at_unix >= ? AND phash <> '' ORDER BY id DESC LIMIT ?`, since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SamplesSince counts clips taken since a time, optionally for one customer.
func (s *SQLite) SamplesSince(ctx context.Context, since time.Time, customer string) (int, error) {
	var n int
	var err error
	if customer == "" {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE sampled = 1 AND received_unix >= ?`, since.Unix()).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE sampled = 1 AND customer = ? AND received_unix >= ?`, customer, since.Unix()).Scan(&n)
	}
	return n, err
}
