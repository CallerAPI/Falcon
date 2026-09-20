package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/alerts"
	"github.com/callerapi/falcon/internal/store"
)

const kvAlertSettings = "alert_settings"

// actor names who made a request: the dashboard user, the token, or the
// query token, always with the address.
func (s *Server) actor(r *http.Request) string {
	who := "token"
	if user, _, ok := r.BasicAuth(); ok && user != "" {
		who = "dashboard:" + user
	} else if r.Header.Get("X-Falcon-Token") == "" && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		if s.Cfg.Token == "" {
			who = "open"
		} else {
			who = "query-token"
		}
	}
	return who + "@" + clientIP(r)
}

// audit records a mutation. It never fails the request.
func (s *Server) audit(r *http.Request, action, subject, detail string) {
	if s.Store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Store.Audit(ctx, store.AuditEntry{Actor: s.actor(r), Action: action, Subject: subject, Detail: detail}); err != nil {
		log.Printf("falcon audit: %v", err)
	}
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.Store.AuditLog(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": entries})
}

// AlertThresholds returns the effective alert settings.
func (s *Server) AlertThresholds(ctx context.Context) alerts.Thresholds {
	th := alerts.Defaults()
	if s.Store == nil {
		return th
	}
	if v, _ := s.Store.KVGet(ctx, kvAlertSettings); v != "" {
		_ = json.Unmarshal([]byte(v), &th)
	}
	return th
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := s.Store.Alerts(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": list, "settings": s.AlertThresholds(r.Context()), "defaults": alerts.Defaults()})
}

func (s *Server) handleAlertSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"settings": s.AlertThresholds(r.Context()), "defaults": alerts.Defaults()})
	case http.MethodPut, http.MethodPost:
		th := s.AlertThresholds(r.Context())
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&th); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		th.WebhookURL = strings.TrimSpace(th.WebhookURL)
		if th.WebhookURL != "" && !strings.HasPrefix(th.WebhookURL, "https://") && !strings.HasPrefix(th.WebhookURL, "http://") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "alert_webhook_url must be http or https"})
			return
		}
		for name, v := range map[string]int{"alert_min_calls": th.MinCalls, "alert_signer_reject_pct": th.SignerRejectPct, "alert_reject_pct": th.RejectPct, "alert_verify_fail_pct": th.VerifyFailPct, "alert_trust_stale_hours": th.TrustStaleHours} {
			if v < 0 || v > 100000 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": name + " out of range"})
				return
			}
		}
		b, _ := json.Marshal(th)
		if err := s.Store.KVSet(r.Context(), kvAlertSettings, string(b)); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		s.audit(r, "alerts.settings", "alerts", redactWebhook(string(b)))
		writeJSON(w, http.StatusOK, map[string]any{"settings": th})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or PUT"})
	}
}

func redactWebhook(js string) string {
	var m map[string]any
	if json.Unmarshal([]byte(js), &m) == nil {
		if u, ok := m["alert_webhook_url"].(string); ok && u != "" {
			m["alert_webhook_url"] = "set"
		}
		if b, err := json.Marshal(m); err == nil {
			return string(b)
		}
	}
	return ""
}

func (s *Server) handleAlertTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	th := s.AlertThresholds(r.Context())
	if th.WebhookURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no alert_webhook_url set"})
		return
	}
	if s.Alerts == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "alert watcher is not running"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	err := s.Alerts.Deliver(ctx, th.WebhookURL, alerts.Fired{Key: "test", Severity: "info", Title: "Falcon test alert", Detail: "Sent from the System view. If you can read this, alerts reach you."})
	s.audit(r, "alerts.test", "alerts", "")
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": true})
}

// handleTraceback builds the pack a traceback request asks for: every
// matching event as CSV and JSON, each raw INVITE as a file, the signer
// certificate chains that are still cached, and a README that explains the
// fields. Local data, unredacted: it is the operator's own record.
func (s *Server) handleTraceback(w http.ResponseWriter, r *http.Request) {
	f := filterFrom(r)
	if f.SPC == "" && f.Number == "" && f.IP == "" && f.Fingerprint == "" && f.Provider == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "give at least one of spc, number, ip, fingerprint, provider"})
		return
	}
	f.Limit = 500
	const maxEvents = 5000

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	now := time.Now().UTC()

	csvBuf := &bytes.Buffer{}
	cw := csv.NewWriter(csvBuf)
	_ = cw.Write([]string{"event_id", "received_at_utc", "action", "risk_score", "calling_number", "called_number", "source_ip", "source_provider", "attestation", "verstat", "signer_spc", "signer_name", "fingerprint", "user_agent", "call_id", "switch", "reasons", "x5u"})
	var all []store.Event
	x5us := map[string]string{}
	for len(all) < maxEvents {
		events, err := s.Store.Query(r.Context(), f)
		if err != nil || len(events) == 0 {
			break
		}
		for _, ev := range events {
			full, err := s.Store.Get(r.Context(), ev.ID)
			if err == nil {
				ev = full
			}
			x5u := ""
			if len(ev.Shaken) > 0 {
				var sh struct {
					X5U string `json:"x5u"`
				}
				if json.Unmarshal(ev.Shaken, &sh) == nil {
					x5u = sh.X5U
				}
			}
			if x5u != "" && ev.SignerSPC != "" {
				x5us[ev.SignerSPC] = x5u
			}
			codes := make([]string, 0, len(ev.Reasons))
			for _, rs := range ev.Reasons {
				codes = append(codes, rs.Code)
			}
			_ = cw.Write([]string{
				strconv.FormatInt(ev.ID, 10), ev.ReceivedAt.UTC().Format(time.RFC3339Nano), string(ev.Action), strconv.Itoa(ev.RiskScore),
				ev.From, ev.To, ev.SourceIP, ev.Provider, ev.Attest, ev.Verstat, ev.SignerSPC, ev.SignerName, ev.Fingerprint,
				ev.UserAgent, ev.CallID, ev.Switch, strings.Join(codes, "|"), x5u,
			})
			if ev.RawSIP != "" {
				fw, _ := zw.Create(fmt.Sprintf("sip/%d.sip", ev.ID))
				_, _ = io.WriteString(fw, ev.RawSIP)
			}
			ev.RawSIP = ""
			all = append(all, ev)
		}
		f.BeforeID = events[len(events)-1].ID
		if len(events) < f.Limit {
			break
		}
	}
	cw.Flush()
	fw, _ := zw.Create("events.csv")
	_, _ = fw.Write(csvBuf.Bytes())
	fw, _ = zw.Create("events.json")
	_ = json.NewEncoder(fw).Encode(all)

	certs := 0
	if s.Verifier != nil {
		for spc, x5u := range x5us {
			if pemBytes := s.Verifier.CachedChainPEM(x5u); len(pemBytes) > 0 {
				fw, _ := zw.Create("certificates/spc-" + sanitize(spc) + ".pem")
				_, _ = fw.Write(pemBytes)
				certs++
			}
		}
	}

	summary := map[string]any{
		"generated_at":      now,
		"generated_by":      "falcon " + Version,
		"install_id":        s.InstallID,
		"filter":            map[string]any{"spc": f.SPC, "number": f.Number, "ip": f.IP, "fingerprint": f.Fingerprint, "provider": f.Provider, "from": f.From, "to": f.To},
		"events":            len(all),
		"truncated":         len(all) >= maxEvents,
		"signer_x5u":        x5us,
		"certificate_files": certs,
	}
	fw, _ = zw.Create("summary.json")
	_ = json.NewEncoder(fw).Encode(summary)
	fw, _ = zw.Create("README.txt")
	_, _ = io.WriteString(fw, tracebackReadme)
	_ = zw.Close()

	name := "falcon-traceback-" + now.Format("20060102-150405") + ".zip"
	s.audit(r, "traceback.export", firstNonEmpty(f.SPC, f.Number, f.IP, f.Fingerprint, f.Provider), fmt.Sprintf("%d events", len(all)))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	_, _ = w.Write(buf.Bytes())
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

const tracebackReadme = `Falcon traceback pack

This archive answers a traceback request for the calls matched by the
filter in summary.json. It was produced on the operator's own Falcon
install from local records. Nothing in it was fetched from a third party
except the signer certificate chains, which were retrieved from the URL in
each call's PASSporT at verification time.

Files
  summary.json      Filter, counts, generator, signer certificate URLs.
  events.csv        One row per call. Columns are listed below.
  events.json       The same calls with full reasons and verification.
  sip/<id>.sip      The raw INVITE as received, one file per call, when
                    raw SIP retention still held it.
  certificates/     The signer certificate chain per SPC, PEM, when the
                    verifier cache still held it.

Columns in events.csv
  event_id          Local id, matches sip/<id>.sip and events.json.
  received_at_utc   When the switch asked Falcon.
  action            allow, flag, challenge, or reject.
  risk_score        0 to 100.
  calling_number    From or P-Asserted-Identity user, E.164 when possible.
  called_number     To user.
  source_ip         Address the INVITE came from, as the switch reported.
  source_provider   Provider behind the source IP, from the IP intel table.
  attestation       A, B, or C from the PASSporT.
  verstat           TN-Validation-Passed, TN-Validation-Failed, or
                    No-TN-Validation.
  signer_spc        Service Provider Code from the signing certificate.
  signer_name       Organisation from the signing certificate.
  fingerprint       Hash of the sending software's habits, not the parties.
  user_agent        As sent.
  call_id           As sent.
  switch            Label the adapter attached.
  reasons           Reason codes, pipe separated.
  x5u               Certificate URL from the PASSporT.

Handling
  These files name subscribers. Send them only to the party that asked,
  over the channel they specified, and delete the copy when the case
  closes.
`
