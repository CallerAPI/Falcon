package share

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

// FuzzRedact holds the one invariant that matters: whatever the SIP looks
// like, the called number's digits never appear in the shared payload.
func FuzzRedact(f *testing.F) {
	f.Add(invite, "+14155550123", "+13125550188")
	f.Add("INVITE sip:4155550123@x SIP/2.0\r\nTo: 4155550123\r\nX: 14155550123;tel:+1-415-555-0123\r\n\r\n", "4155550123", "+13125550188")
	f.Add("garbage\x00\xff\r\n\r\n", "+14155550123", "")
	f.Add("", "", "")
	// CI found this: From has a long zero run, To is seven zeros.
	f.Add("000\r\n\r\n", "0000000", "1111000000000000000000")
	f.Fuzz(func(t *testing.T, raw, to, from string) {
		ev := store.Event{
			ReceivedAt: time.Now(), Action: score.ActionReject, From: from, To: to,
			CallID: raw, UserAgent: to, RawSIP: raw, Switch: to,
			Reasons: []score.Reason{{Code: "x", Detail: raw}},
		}
		out := Redact(ev, []byte("k"))
		if _, err := json.Marshal(out); err != nil {
			t.Fatal(err)
		}
		// Check the raw strings, not the JSON: escaping like \u0001 can
		// manufacture digit sequences that are not in the data.
		fields := []string{out.To, out.From, out.CallID, out.UserAgent, out.Switch, out.RawSIP}
		for _, r := range out.Reasons {
			fields = append(fields, r.Detail)
		}
		called := digits(to)
		if len(called) >= 7 && strings.Contains(strings.Join(fields, "\n"), called) {
			t.Fatalf("called digits %q leaked:\n%q", called, fields)
		}
		if out.To != Redacted {
			t.Fatalf("to = %q", out.To)
		}
	})
}
