package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/ipintel"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

// A clean INVITE from a source listed as block is rejected on the IP alone,
// the provider name is on the event, and the status endpoint reports the table.
func TestScreenIPIntelBlock(t *testing.T) {
	dir := t.TempDir()
	db, err := store.OpenSQLite(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	csvPath := filepath.Join(dir, "ipintel.csv")
	if err := os.WriteFile(csvPath, []byte("cidr,provider,risk,tags\n198.51.100.0/24,Shady Gateway LLC,block,gateway\n203.0.113.0/24,Good Carrier,trusted,carrier\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	table := ipintel.New(csvPath, "", "", time.Hour)
	table.Load(context.Background())

	cfg := config.Config{FailOpen: true, Token: "secret", IPIntelFile: csvPath, StoreRawSIP: true}
	srv := &Server{
		Cfg:       cfg,
		Engine:    score.NewEngine(score.Thresholds{Flag: 40, Challenge: 60, Reject: 80}, score.Limits{Window: time.Minute, IP: 30, From: 20, Scan: 15}),
		Store:     db,
		IPIntel:   table,
		InstallID: "test",
	}
	clean := "INVITE sip:+15551212@ex SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 198.51.100.20;branch=z9hG4bK1\r\n" +
		"From: <sip:+14155550100@ex>;tag=1\r\n" +
		"To: <sip:+15551212@ex>\r\n" +
		"Call-ID: demo\r\n" +
		"User-Agent: Acme-SBC/1.0\r\n" +
		"Max-Forwards: 70\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 0\r\n\r\n" +
		"v=0\r\no=- 1 1 IN IP4 198.51.100.20\r\nc=IN IP4 198.51.100.20\r\nm=audio 4000 RTP/AVP 0\r\n"
	screen := func(ip string) score.Result {
		body, _ := json.Marshal(map[string]string{"switch": "test", "source_ip": ip, "raw_sip": clean})
		req := httptest.NewRequest(http.MethodPost, "/v1/screen", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Falcon-Token", "secret")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("status %d body %s", w.Code, w.Body.String())
		}
		var res score.Result
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		return res
	}

	bad := screen("198.51.100.20")
	if bad.Action != score.ActionReject || bad.Headers["X-Falcon-Block"] != "ip_intel" {
		t.Fatalf("block row must hard reject: %+v", bad)
	}
	if bad.Signals.IPProvider != "Shady Gateway LLC" || bad.Headers["X-Falcon-Provider"] != "Shady Gateway LLC" {
		t.Fatalf("provider missing: %+v", bad.Signals)
	}

	good := screen("203.0.113.9")
	if good.Action != score.ActionAllow || good.Signals.IPProvider != "Good Carrier" || good.Signals.IPRisk != "trusted" {
		t.Fatalf("trusted row must name the provider and add no weight: %+v", good)
	}

	unknown := screen("192.0.2.1")
	if unknown.Signals.IPProvider != "" {
		t.Fatalf("unlisted ip must have no provider: %+v", unknown.Signals)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		events, err := db.Recent(context.Background(), 5)
		if err == nil && len(events) == 3 {
			seen := map[string]bool{}
			for _, ev := range events {
				seen[ev.Provider] = true
			}
			if !seen["Shady Gateway LLC"] || !seen["Good Carrier"] {
				t.Fatalf("provider not persisted: %+v", events)
			}
			st, err := db.Stats(context.Background(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			if err != nil || len(st.TopProviders) != 2 {
				t.Fatalf("top providers: %+v %v", st.TopProviders, err)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req.Header.Set("X-Falcon-Token", "secret")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var status struct {
		IPIntel struct {
			Configured bool `json:"configured"`
			Count      int  `json:"count"`
		} `json:"ip_intel"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.IPIntel.Configured || status.IPIntel.Count != 2 {
		t.Fatalf("status: %+v", status.IPIntel)
	}
}
