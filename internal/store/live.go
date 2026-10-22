package store

import (
	"context"
	"time"
)

// LiveCall is a bridged call whose far end answered, with the SIP messages
// that set up each leg. A row that is still here when Falcon starts is a
// call a crash left up. Falcon hangs it up from these messages.
type LiveCall struct {
	CallID string
	// AInvite is the INVITE from the switch. AOK is Falcon's 200 to it,
	// empty while the caller is not answered.
	AInvite string
	AOK     string
	// BInvite is the INVITE Falcon sent. BOK is the far end's 200.
	BInvite string
	BOK     string
	Saved   time.Time
}

// SaveLiveCall stores or replaces the row for one call.
func (s *SQLite) SaveLiveCall(ctx context.Context, c LiveCall) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO live_calls (call_id, a_invite, a_ok, b_invite, b_ok, saved_unix) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(call_id) DO UPDATE SET a_invite = excluded.a_invite, a_ok = excluded.a_ok,
  b_invite = excluded.b_invite, b_ok = excluded.b_ok, saved_unix = excluded.saved_unix`,
		c.CallID, c.AInvite, c.AOK, c.BInvite, c.BOK, c.Saved.UTC().Unix())
	return err
}

// DeleteLiveCall removes the row of a call that ended.
func (s *SQLite) DeleteLiveCall(ctx context.Context, callID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM live_calls WHERE call_id = ?`, callID)
	return err
}

// LiveCalls lists every stored row.
func (s *SQLite) LiveCalls(ctx context.Context) ([]LiveCall, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT call_id, a_invite, a_ok, b_invite, b_ok, saved_unix FROM live_calls`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LiveCall
	for rows.Next() {
		var c LiveCall
		var saved int64
		if err := rows.Scan(&c.CallID, &c.AInvite, &c.AOK, &c.BInvite, &c.BOK, &saved); err != nil {
			return nil, err
		}
		c.Saved = time.Unix(saved, 0).UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}
