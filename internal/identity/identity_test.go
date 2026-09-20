package identity

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/store"
)

func TestKeyIsStableAndSignaturesVerify(t *testing.T) {
	ctx := context.Background()
	db, err := store.OpenSQLite(t.TempDir() + "/k.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	k1, err := Load(ctx, db, "inst")
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := Load(ctx, db, "inst")
	if k1.Public() != k2.Public() {
		t.Fatal("key changed between loads")
	}

	body := []byte(`{"events":[]}`)
	req, _ := http.NewRequest(http.MethodPost, "https://api.callerapi.com/api/falcon/v1/telemetry", bytes.NewReader(body))
	k1.Sign(req, body)
	id, pub, err := Verify(req, body, 10*time.Minute)
	if err != nil || id != "inst" || len(pub) != 32 {
		t.Fatalf("verify: %v id=%q", err, id)
	}

	if _, _, err := Verify(req, []byte(`{"events":[{}]}`), 10*time.Minute); err == nil {
		t.Fatal("tampered body verified")
	}
	req.Header.Set(HeaderInstall, "other")
	if _, _, err := Verify(req, body, 10*time.Minute); err == nil {
		t.Fatal("changed install id verified")
	}
	req.Header.Set(HeaderInstall, "inst")
	req.Header.Set(HeaderTimestamp, "1000000000")
	if _, _, err := Verify(req, body, 10*time.Minute); err == nil {
		t.Fatal("stale timestamp verified")
	}
}
