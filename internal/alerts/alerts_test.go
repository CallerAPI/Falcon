package alerts

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

func seed(t *testing.T, db store.Store, n int, action score.Action, spc, verstat string) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := db.Insert(context.Background(), store.Event{
			ReceivedAt: time.Now().UTC(), Action: action, RiskScore: 50,
			From: "+1312555" + itoa(1000+i), To: "+14155550100", SourceIP: "203.0.113.9",
			SignerSPC: spc, SignerName: "Kestrel Gateway", Verstat: verstat, Attest: "A",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestAlertsFireOnceWithinCooldownAndDeliver(t *testing.T) {
	db, err := store.OpenSQLite(t.TempDir() + "/a.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seed(t, db, 60, score.ActionReject, "8080", "TN-Validation-Failed")
	seed(t, db, 20, score.ActionAllow, "7421", "TN-Validation-Passed")

	var got []map[string]any
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		got = append(got, m)
	}))
	defer hook.Close()

	th := Defaults()
	th.WebhookURL = hook.URL
	w := &Watcher{Sources: Sources{
		Store:      db,
		Thresholds: func(context.Context) Thresholds { return th },
		TrustAge:   func() (time.Duration, bool) { return 30 * time.Hour, true },
		Version:    "test",
	}}

	fired := w.Evaluate(context.Background())
	keys := map[string]bool{}
	for _, f := range fired {
		keys[f.Key] = true
	}
	for _, want := range []string{"reject_rate", "verify_fail_rate", "signer_reject:8080", "trust_stale"} {
		if !keys[want] {
			t.Fatalf("missing %s in %v", want, keys)
		}
	}
	if keys["signer_reject:7421"] {
		t.Fatal("clean signer alerted")
	}

	w.Tick(context.Background())
	w.Tick(context.Background())
	if len(got) != len(fired) {
		t.Fatalf("webhook calls = %d, want %d (cooldown must suppress the second tick)", len(got), len(fired))
	}
	if txt, _ := got[0]["text"].(string); !strings.HasPrefix(txt, "[falcon ") {
		t.Fatalf("slack text: %q", txt)
	}
	stored, _ := db.Alerts(context.Background(), 10)
	if len(stored) != len(fired) || !stored[0].Delivered {
		t.Fatalf("stored alerts: %+v", stored)
	}
}

func TestAlertsRespectMinCalls(t *testing.T) {
	db, _ := store.OpenSQLite(t.TempDir() + "/b.db")
	defer db.Close()
	seed(t, db, 10, score.ActionReject, "8080", "TN-Validation-Failed")
	w := &Watcher{Sources: Sources{Store: db, Thresholds: func(context.Context) Thresholds { return Defaults() }}}
	if fired := w.Evaluate(context.Background()); len(fired) != 0 {
		t.Fatalf("fired below min calls: %+v", fired)
	}
}
