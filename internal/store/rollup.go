package store

import (
	"context"
	"strings"
	"time"
)

// RollupRow is one hour of clean inbound calls for one key. Dim is signer,
// fingerprint, caller, or install. A clean call is allowed with no honeypot
// hit, no failed verification, and no voice category. It matches
// share.Evidence.
type RollupRow struct {
	Dim         string
	Key         string
	Label       string
	SPC         string
	Fingerprint string
	Calls       int
	Verified    int
	Completed   int
	Answered    int
	TalkSeconds int
	Callees     int
	FirstSeen   time.Time
	LastSeen    time.Time
}

// RollupStore builds the hourly counts of clean calls.
type RollupStore interface {
	CleanRollups(ctx context.Context, from, to time.Time, minCallerCalls int) ([]RollupRow, error)
}

// cleanWhere selects the clean inbound calls in a window. Outbound calls
// carry the operator's own subscribers as the calling number, so they never
// leave the host.
const cleanWhere = `received_unix >= ? AND received_unix < ? AND action = 'allow' AND COALESCE(honeypot, 0) = 0
  AND COALESCE(verstat, '') != 'TN-Validation-Failed' AND COALESCE(direction, '') != 'outbound'
  AND NOT (COALESCE(sampled, 0) = 1 AND EXISTS (SELECT 1 FROM voice_samples v WHERE v.event_id = events.id AND COALESCE(v.category, '') NOT IN ('', 'none')))`

// verifiedSigner is the signer of a PASSporT Falcon verified. A signer the
// switch reported is left out, as in the shared event.
const verifiedSigner = `CASE WHEN COALESCE(shaken, '') NOT LIKE '%"source":"switch"%' THEN COALESCE(signer_spc, '') ELSE '' END`

const rollupCounts = `COUNT(*),
  SUM(CASE WHEN verstat = 'TN-Validation-Passed' THEN 1 ELSE 0 END),
  SUM(CASE WHEN answered IS NOT NULL THEN 1 ELSE 0 END),
  SUM(CASE WHEN answered = 1 THEN 1 ELSE 0 END),
  SUM(CASE WHEN answered = 1 THEN COALESCE(duration_s, 0) ELSE 0 END),
  MIN(received_unix), MAX(received_unix)`

// CleanRollups counts the clean calls in [from, to). A caller needs
// minCallerCalls calls in the window to get a row. A caller whose number
// holds the called number is left out: that is the subscriber's own number.
func (s *SQLite) CleanRollups(ctx context.Context, from, to time.Time, minCallerCalls int) ([]RollupRow, error) {
	lo, hi := from.Unix(), to.Unix()
	queries := []struct {
		dim, key, label, extra, groupBy string
		args                            []any
	}{
		{"install", `''`, `''`, ``, ``, nil},
		{"signer", verifiedSigner, `COALESCE(MAX(COALESCE(signer_name, '')), '')`, ` AND ` + verifiedSigner + ` != ''`, ` GROUP BY 1`, nil},
		{"fingerprint", `COALESCE(fingerprint, '')`, `COALESCE(MAX(COALESCE(user_agent, '')), '')`, ` AND COALESCE(fingerprint, '') != ''`, ` GROUP BY 1`, nil},
		{"caller", `from_num`, `''`,
			` AND from_num LIKE '+%' AND length(from_num) BETWEEN 8 AND 16
  AND (COALESCE(to_num, '') = '' OR instr(replace(from_num, '+', ''), replace(to_num, '+', '')) = 0)`,
			` GROUP BY 1 HAVING COUNT(*) >= ?`, []any{max(minCallerCalls, 1)}},
	}
	var out []RollupRow
	for _, q := range queries {
		sql := `SELECT ` + q.key + `, ` + q.label + `, COALESCE(MAX(` + verifiedSigner + `), ''), COALESCE(MAX(COALESCE(fingerprint, '')), ''), ` + rollupCounts +
			` FROM events WHERE ` + cleanWhere + q.extra + q.groupBy
		args := append([]any{lo, hi}, q.args...)
		rows, err := s.db.QueryContext(ctx, sql, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			r := RollupRow{Dim: q.dim}
			var first, last *int64
			var verified, completed, answered, talk *int
			if err := rows.Scan(&r.Key, &r.Label, &r.SPC, &r.Fingerprint, &r.Calls, &verified, &completed, &answered, &talk, &first, &last); err != nil {
				rows.Close()
				return nil, err
			}
			if r.Calls == 0 {
				continue
			}
			r.Verified, r.Completed, r.Answered, r.TalkSeconds = deref(verified), deref(completed), deref(answered), deref(talk)
			if first != nil {
				r.FirstSeen = time.Unix(*first, 0).UTC()
			}
			if last != nil {
				r.LastSeen = time.Unix(*last, 0).UTC()
			}
			if q.dim != "caller" {
				r.SPC, r.Fingerprint = "", ""
			}
			out = append(out, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, s.addCallees(ctx, out, hi)
}

// addCallees counts the distinct called numbers of each caller row over the
// 24 hours that end at hi, across every inbound call.
func (s *SQLite) addCallees(ctx context.Context, rows []RollupRow, hi int64) error {
	idx := map[string]int{}
	var numbers []string
	for i, r := range rows {
		if r.Dim == "caller" {
			idx[r.Key] = i
			numbers = append(numbers, r.Key)
		}
	}
	for start := 0; start < len(numbers); start += 500 {
		chunk := numbers[start:min(start+500, len(numbers))]
		args := []any{hi - 24*3600, hi}
		for _, n := range chunk {
			args = append(args, n)
		}
		q := `SELECT from_num, COUNT(DISTINCT to_num) FROM events WHERE received_unix >= ? AND received_unix < ?
  AND COALESCE(direction, '') != 'outbound' AND COALESCE(to_num, '') != '' AND from_num IN (` + placeholders(len(chunk)) + `) GROUP BY from_num`
		res, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		for res.Next() {
			var n string
			var c int
			if err := res.Scan(&n, &c); err != nil {
				res.Close()
				return err
			}
			if i, ok := idx[strings.TrimSpace(n)]; ok {
				rows[i].Callees = c
			}
		}
		res.Close()
		if err := res.Err(); err != nil {
			return err
		}
	}
	return nil
}

func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
