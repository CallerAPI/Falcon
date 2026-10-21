package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/compliance"
	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/numbercheck"
)

// Module is one built-in capability and its state on this install.
type Module struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
	// State is on, off, needs_key, or error.
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	// Enable is what turns it on when it is off.
	Enable string `json:"enable,omitempty"`
	Paid   bool   `json:"paid,omitempty"`
}

func (s *Server) modules(ctx context.Context) []Module {
	key := s.Cfg.CallerAPIKey != ""
	needsKey := func(m Module) Module {
		if !key {
			m.State, m.Enable = "needs_key", "Set CALLERAPI_API_KEY"
		}
		return m
	}
	var out []Module

	sh := Module{ID: "shaken", Title: "STIR/SHAKEN verification", Summary: "Checks every signature, names the provider that signed, and flags failures.", State: "off", Enable: "FALCON_SHAKEN=true"}
	if s.Verifier != nil {
		sh.State, sh.Enable = "on", ""
		if s.Trust != nil {
			if st := s.Trust.Status(); st.Roots == 0 {
				sh.State, sh.Detail = "error", "The STI-PA trust list is not loaded."
			} else {
				sh.Detail = fmt.Sprintf("%d trusted roots, %d revoked certificates", st.Roots, st.Revoked)
			}
		}
	}
	out = append(out, sh)

	feed := Module{ID: "spam_list", Title: "Spam list", Summary: "Blocks numbers on the CallerAPI spam list at the INVITE.", State: "off", Enable: "FALCON_SPAM_FEED=true", Paid: true}
	if s.Feed != nil && s.Cfg.FeedEnabled() {
		n, at, errText := s.Feed.Status()
		feed.State, feed.Enable, feed.Detail = "on", "", fmt.Sprintf("%d numbers, updated %s", n, ago(at))
		if errText != "" {
			feed.State, feed.Detail = "error", errText
		}
	} else {
		feed = needsKey(feed)
	}
	out = append(out, feed)

	live := Module{ID: "live_reputation", Title: "Live reputation", Summary: "Checks each calling number against live CallerAPI reputation. A spam hit flags the call.", State: "off", Enable: "FALCON_VOICE_FIREWALL=true", Paid: true}
	if s.Cfg.FirewallEnabled() {
		live.State, live.Enable = "on", ""
	} else {
		live = needsKey(live)
	}
	out = append(out, live)

	ip := Module{ID: "ip_intel", Title: "Telecom IP fraud list", Summary: "Names the network behind each source address and blocks known fraud ranges.", State: "off", Enable: "FALCON_IP_INTEL=true"}
	if s.IPIntel != nil {
		n, at, errText := s.IPIntel.Status()
		ip.State, ip.Enable, ip.Detail = "on", "", fmt.Sprintf("%d address blocks, updated %s", n, ago(at))
		if errText != "" {
			ip.State, ip.Detail = "error", errText
		}
	}
	out = append(out, ip)

	bcid := Module{ID: "bcid", Title: "Business Caller ID", Summary: "Verifies registered business numbers for free and rejects a spoofed brand.", State: "off", Enable: "FALCON_BCID=true"}
	if s.Cfg.BCIDEnabled() {
		bcid.State, bcid.Enable = "on", ""
	} else {
		bcid = needsKey(bcid)
	}
	out = append(out, bcid)

	net := Module{ID: "network", Title: "Network reputation", Summary: "Scores signers and dialer software from what every sharing install saw this week.", State: "off", Enable: "FALCON_SHARE=true and FALCON_REPUTATION=true"}
	if s.Reputation != nil {
		st := s.Reputation.Status()
		net.State, net.Enable, net.Detail = "on", "", fmt.Sprintf("%d signers, %d tools", st.Signers, st.Fingerprints)
		if st.Error != "" {
			net.Detail = "Waiting for the first feed: " + st.Error
		}
	}
	out = append(out, net)

	fcc := Module{ID: "fcc", Title: "FCC autopilot", Summary: "Checks your upstream carriers against FCC orders and the Robocall Mitigation Database, and blocks the ones you may not take calls from.", State: "off", Enable: "FALCON_FCC=true"}
	if s.Compliance != nil {
		st := s.Compliance.Status()
		fcc.State, fcc.Enable = "on", ""
		action := "Alerts only."
		if s.FCCMode(ctx) == compliance.ModeEnforce {
			action = "Blocks upstreams under an FCC order."
		}
		fcc.Detail = fmt.Sprintf("%d providers on the list. %s", st.Providers, action)
		if st.Providers == 0 {
			fcc.Detail = "Waiting for the first list."
			if st.Error != "" {
				fcc.Detail = "Waiting for the first list: " + st.Error
			}
		}
	}
	out = append(out, fcc)

	br := Module{ID: "bridge", Title: "Call bridge and recording", Summary: "Carries suspicious calls back to your switch, records both sides, and hears false answers.", State: "off", Enable: "FALCON_SIP_LISTEN and FALCON_SIP_MODE=bridge"}
	if s.Media != nil {
		br.State, br.Enable, br.Detail = "on", "", fmt.Sprintf("%d calls up, room for %d", s.Media.Active(), s.Media.Capacity())
	}
	out = append(out, br)

	fasMode := s.Settings(ctx).FASMode
	fas := Module{ID: "fas", Title: "FAS guard", Summary: "Hears ringback, busy, intercepts, and silence after a vendor answers.", State: "off"}
	switch {
	case s.Media == nil:
		fas.Enable = "Turn on the call bridge"
	case fasMode == config.FASOff:
		fas.Enable = "Settings, FAS guard"
	default:
		fas.State, fas.Detail = "on", map[string]string{config.FASMonitor: "Watching. Answers pass at once.", config.FASEnforce: "Holding answers until a person speaks."}[fasMode]
	}
	out = append(out, fas)

	ai := Module{ID: "voice_ai", Title: "AI voice analysis", Summary: "Transcribes recordings by speaker and sorts scams into the CallerAPI categories.", State: "off", Enable: "FALCON_VOICE_PROVIDER=callerapi or openai"}
	if s.VoiceProvider != nil {
		ai.State, ai.Enable, ai.Detail = "on", "", providerName(s.VoiceProvider)
	}
	out = append(out, ai)

	nc := Module{ID: "number_check", Title: "Number check", Summary: "Keeps a list of your own numbers and rechecks their reputation on a schedule. 1 credit per number.", State: "off", Paid: true}
	if s.NumberCheck != nil {
		nc.State = "on"
	} else {
		nc = needsKey(nc)
	}
	out = append(out, nc)
	return out
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t).Round(time.Minute)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

func (s *Server) handleModules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": s.modules(r.Context())})
}

// handleNumberCheck serves the built-in number check: view, import, and
// schedule. The browser talks to Falcon only.
func (s *Server) handleNumberCheck(w http.ResponseWriter, r *http.Request) {
	if s.NumberCheck == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": numbercheck.ErrOff.Error()})
		return
	}
	switch strings.TrimPrefix(r.URL.Path, "/v1/numbercheck/") {
	case "view":
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}
		panel, err := s.NumberCheck.View(r.Context(), r.URL.Query().Get("q"))
		numberCheckReply(w, panel, err)
	case "import":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		body, err := readUpload(r)
		if err != nil || len(body) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "choose a file"})
			return
		}
		panel, err := s.NumberCheck.Import(r.Context(), body)
		if err == nil {
			s.audit(r, "numbercheck.import", "file", fmt.Sprintf("%d bytes", len(body)))
		}
		numberCheckReply(w, panel, err)
	case "schedule":
		var raw []byte
		var err error
		switch r.Method {
		case http.MethodGet:
			raw, err = s.NumberCheck.Schedule(r.Context())
		case http.MethodPut:
			body, rerr := io.ReadAll(io.LimitReader(r.Body, 4096))
			if rerr != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid schedule"})
				return
			}
			raw, err = s.NumberCheck.SaveSchedule(r.Context(), body)
			if err == nil {
				s.audit(r, "numbercheck.schedule", "schedule", string(body))
			}
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or PUT"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func numberCheckReply(w http.ResponseWriter, panel numbercheck.Panel, err error) {
	if errors.Is(err, numbercheck.ErrOff) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, panel)
}

func readUpload(r *http.Request) ([]byte, error) {
	const max = 32 << 20
	if strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(max); err != nil {
			return nil, err
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return io.ReadAll(io.LimitReader(file, max+1))
	}
	return io.ReadAll(io.LimitReader(r.Body, max+1))
}
