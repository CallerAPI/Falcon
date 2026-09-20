// Package demo builds two 30-day Falcon stores for a live Zoom walkthrough.
// Free names cloud and abuse lists. Paid names the voice operator and
// rejects listed spam DIDs. Same week of traffic, different fields.
package demo

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/store"
)

const (
	ProfileFree = "free"
	ProfilePaid = "paid"
	installID   = "demo-falcon-zoom"
)

// Dir is the fixture folder (CSVs and generated DBs).
func Dir(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if v := strings.TrimSpace(os.Getenv("FALCON_DEMO_DIR")); v != "" {
		return v
	}
	wd, err := os.Getwd()
	if err != nil {
		return "examples/demo"
	}
	for _, rel := range []string{"examples/demo", "falcon/examples/demo", "../examples/demo", "../../examples/demo"} {
		p := filepath.Join(wd, rel)
		if fileOK(filepath.Join(p, "ipintel-paid.csv")) {
			return p
		}
	}
	return filepath.Join(wd, "examples/demo")
}

func DBPath(dir, profile string) string {
	return filepath.Join(dir, "falcon-"+profile+".db")
}

func IntelPath(dir, profile string) string {
	if profile == ProfilePaid {
		return filepath.Join(dir, "ipintel-paid.csv")
	}
	return filepath.Join(dir, "ipintel-free.csv")
}

func fileOK(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Size() > 0
}

// Seed writes both profile databases next to the fixture CSVs.
func Seed(dir string) error {
	dir = Dir(dir)
	if !fileOK(IntelPath(dir, ProfilePaid)) || !fileOK(IntelPath(dir, ProfileFree)) {
		return fmt.Errorf("demo fixtures missing in %s (need ipintel-free.csv and ipintel-paid.csv)", dir)
	}
	spam, err := SpamDIDs(dir)
	if err != nil {
		return err
	}
	end := time.Now().UTC().Truncate(time.Hour)
	calls := buildCalls(end, spam)
	for _, profile := range []string{ProfileFree, ProfilePaid} {
		if err := seedProfile(dir, profile, calls, spam, end); err != nil {
			return err
		}
	}
	return nil
}

// Swap copies the seeded profile onto liveDB and returns the intel CSV path.
func Swap(dir, liveDB, profile string) (intel string, err error) {
	profile, err = Normalize(profile)
	if err != nil {
		return "", err
	}
	dir = Dir(dir)
	src := DBPath(dir, profile)
	if !fileOK(src) {
		if err := Seed(dir); err != nil {
			return "", err
		}
	}
	if !fileOK(src) {
		return "", fmt.Errorf("demo seed missing: %s", src)
	}
	if liveDB == "" {
		return IntelPath(dir, profile), nil
	}
	db, err := store.OpenSQLite(liveDB)
	if err != nil {
		return "", err
	}
	if err := db.ReplaceFile(src, liveDB); err != nil {
		_ = db.Close()
		return "", err
	}
	_ = db.Close()
	return IntelPath(dir, profile), nil
}

func Normalize(profile string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case ProfileFree, "oss", "open":
		return ProfileFree, nil
	case ProfilePaid, "addon", "rmd", "provider":
		return ProfilePaid, nil
	default:
		return "", fmt.Errorf("profile must be free or paid")
	}
}

func SpamDIDs(dir string) ([]string, error) {
	path := filepath.Join(Dir(dir), "spam_dids.txt")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		n := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(n, "+") {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no spam DIDs in %s", path)
	}
	return out, sc.Err()
}

type rawCall struct {
	At       time.Time
	Kind     string
	IP       string
	From     string
	To       string
	UA       string
	Switch   string
	Customer string
	Campaign string
}

func buildCalls(end time.Time, spam []string) []rawCall {
	rng := rand.New(rand.NewSource(42))
	start := end.Add(-30 * 24 * time.Hour)
	callees := []string{"+14155550100", "+12125550188", "+13125550120", "+16175550144", "+17205550102"}
	cleanFrom := []string{"+14155550821", "+12125550833", "+13125550844", "+18005551212"}
	switches := []string{"sbc-west-1", "sbc-east-1", "kamailio-eu"}
	customers := []string{"healthco", "wholesale-eu", "retail-cx"}
	out := make([]rawCall, 0, 5000)
	for day := 0; day < 30; day++ {
		dayStart := start.Add(time.Duration(day) * 24 * time.Hour)
		n := 95 + rng.Intn(35)
		attack := day == 4 || day == 12 || day == 19 || day == 26
		if attack {
			n += 220
		}
		for i := 0; i < n; i++ {
			at := dayStart.Add(time.Duration(rng.Intn(24*60)) * time.Minute)
			if at.After(end) {
				at = end.Add(-time.Duration(rng.Intn(40)) * time.Minute)
			}
			c := rawCall{
				At:       at,
				Switch:   switches[rng.Intn(len(switches))],
				Customer: customers[rng.Intn(len(customers))],
				To:       callees[rng.Intn(len(callees))],
			}
			roll := rng.Intn(100)
			switch {
			case attack && roll < 55:
				c.Kind = "spam"
				c.Campaign = "listed-did-burst"
				c.IP = pick(rng, []string{"4.150.191.6", "5.62.61.170", "185.234.52.18"})
				c.From = spam[rng.Intn(len(spam))]
				c.UA = pick(rng, []string{"sipcli/1.8", "friendly-scanner", "VaxSIPUserAgent/3.0"})
			case roll < 12:
				c.Kind = "scanner"
				c.IP = pick(rng, []string{"185.234.52.18", "91.224.92.14"})
				c.From = "+1555" + fmt.Sprintf("%07d", rng.Intn(9000000)+1000000)
				c.UA = pick(rng, []string{"friendly-scanner", "sipvicious", "sipcli/1.8"})
			case roll < 28:
				c.Kind = "cpaas-8x8"
				c.IP = "18.139.118.140"
				c.From = pick(rng, append(cleanFrom, spam[rng.Intn(8)]))
				c.UA = "8x8-UCaaS/4.2"
			case roll < 42:
				c.Kind = "cpaas-zoom"
				c.IP = "121.244.203.200"
				c.From = pick(rng, cleanFrom)
				c.UA = "Zoom-Phone/6.1"
			case roll < 50:
				c.Kind = "gateway"
				c.IP = "135.84.127.10"
				c.From = pick(rng, append(cleanFrom, spam[rng.Intn(len(spam))]))
				c.UA = "Asterisk PBX 18.20.0"
			case roll < 58:
				c.Kind = "wholesale"
				c.IP = "162.211.102.40"
				c.From = pick(rng, append(cleanFrom, spam[rng.Intn(len(spam))]))
				c.UA = "voip.ms-gateway/2.0"
			case roll < 66:
				c.Kind = "shared-gw"
				c.IP = "23.167.192.20"
				c.From = pick(rng, cleanFrom)
				c.UA = "46labs-SBC/1.9"
			case roll < 78:
				c.Kind = "junk"
				c.IP = pick(rng, []string{"4.150.191.6", "5.62.61.170"})
				c.From = spam[rng.Intn(len(spam))]
				c.UA = pick(rng, []string{"sipcli/1.8", "Twilio Proxy/1.1"})
			default:
				c.Kind = "clean"
				c.IP = pick(rng, []string{"73.162.10.40", "24.7.88.19"})
				c.From = cleanFrom[rng.Intn(len(cleanFrom))]
				c.UA = pick(rng, []string{"Cisco-CUCM/14.0", "PolycomVVX/6.4"})
			}
			if strings.HasPrefix(c.From, "+15551119999") {
				c.To = "+15551119999"
			}
			if attack && i%40 == 0 {
				c.To = "+15551119999"
			}
			out = append(out, c)
		}
	}
	return out
}

func pick(rng *rand.Rand, xs []string) string {
	return xs[rng.Intn(len(xs))]
}

func seedProfile(dir, profile string, calls []rawCall, spam []string, end time.Time) error {
	path := DBPath(dir, profile)
	_ = os.Remove(path)
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")
	db, err := store.OpenSQLite(path)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.KVSet(ctx, "install_id", installID); err != nil {
		return err
	}
	if err := db.KVSet(ctx, "demo_profile", profile); err != nil {
		return err
	}
	paid := profile == ProfilePaid
	spamSet := map[string]struct{}{}
	if paid {
		for _, n := range spam {
			spamSet[n] = struct{}{}
		}
	}
	customers := []store.Customer{
		{ID: "healthco", Name: "HealthCo UCaaS", DIDs: []string{"+14155550100", "+1415555*"}},
		{ID: "wholesale-eu", Name: "EU Wholesale", DIDs: []string{"+442071234000", "+44*"}},
		{ID: "retail-cx", Name: "Retail CX", DIDs: []string{"+12125550188"}},
	}
	for _, c := range customers {
		if err := db.PutCustomer(ctx, c); err != nil {
			return err
		}
	}
	if err := addRules(ctx, db, paid); err != nil {
		return err
	}
	for i, raw := range calls {
		ev := enrich(raw, paid, spamSet, i)
		id, err := db.Insert(ctx, ev)
		if err != nil {
			return err
		}
		if ev.Action == score.ActionAllow && i%3 == 0 {
			ans := i%5 != 0
			dur := 8 + i%90
			if !ans {
				dur = 0
			}
			if _, err := db.SetOutcome(ctx, ev.CallID, store.Outcome{Answered: ans, DurationS: dur, HangupCause: hangup(ans)}); err != nil {
				_ = id
				return err
			}
		}
	}
	if err := addAlerts(ctx, db, paid, end); err != nil {
		return err
	}
	return db.Checkpoint()
}

func hangup(answered bool) string {
	if answered {
		return "NORMAL_CLEARING"
	}
	return "NO_ANSWER"
}

func addRules(ctx context.Context, db store.Store, paid bool) error {
	rules := []lists.Rule{
		{Kind: lists.Honeypot, Subject: lists.Number, Value: "+15551119999", Note: "unassigned test DID"},
	}
	if paid {
		rules = append(rules,
			lists.Rule{Kind: lists.Deny, Subject: lists.IP, Value: "5.62.61.0/24", Note: "repeat voip abuse"},
			lists.Rule{Kind: lists.Deny, Subject: lists.SPC, Value: "9999", Note: "unsigned mill under traceback"},
		)
	}
	for _, r := range rules {
		if _, err := db.AddRule(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func addAlerts(ctx context.Context, db store.Store, paid bool, end time.Time) error {
	items := []store.Alert{
		{At: end.Add(-6 * 24 * time.Hour), Key: "scan-burst", Severity: "high", Title: "SIP scanner burst", Detail: "friendly-scanner from 185.234.52.18", Delivered: true},
	}
	if paid {
		items = append(items,
			store.Alert{At: end.Add(-4 * 24 * time.Hour), Key: "spam-feed", Severity: "high", Title: "Listed spam DIDs on cloud voice", Detail: "Azure and Avast source IPs with feed hits", Delivered: true},
			store.Alert{At: end.Add(-19 * 24 * time.Hour), Key: "cpaas-keep", Severity: "info", Title: "Official 8x8 and Zoom allowed", Detail: "Same AWS and Tata ranges that free intel flags as datacenter", Delivered: true},
		)
	} else {
		items = append(items,
			store.Alert{At: end.Add(-4 * 24 * time.Hour), Key: "dc-false", Severity: "medium", Title: "Datacenter flags on live CPaaS", Detail: "8x8 and Zoom look like cloud. No provider overlay.", Delivered: true},
		)
	}
	for _, a := range items {
		if _, err := db.AddAlert(ctx, a); err != nil {
			return err
		}
	}
	return nil
}

func enrich(raw rawCall, paid bool, spam map[string]struct{}, i int) store.Event {
	_, listed := spam[raw.From]
	ev := store.Event{
		ReceivedAt:  raw.At,
		SourceIP:    raw.IP,
		From:        raw.From,
		To:          raw.To,
		CallID:      fmt.Sprintf("demo-%s-%d", raw.At.Format("20060102"), i),
		UserAgent:   raw.UA,
		Switch:      raw.Switch,
		Customer:    raw.Customer,
		Direction:   "inbound",
		Fingerprint: "ua:" + strings.ToLower(strings.ReplaceAll(raw.UA, " ", "")),
		Honeypot:    raw.To == "+15551119999",
	}
	switch raw.Kind {
	case "scanner":
		ev.Action = score.ActionReject
		ev.RiskScore = 96
		ev.Reasons = []score.Reason{{Code: "scanner_ua", Category: "fingerprint", Weight: 80, Detail: "Known SIP scanner user-agent"}}
	case "cpaas-8x8":
		if paid {
			ev.Provider = "8x8, Inc."
			ev.Attest = "A"
			ev.Verstat = "TN-Validation-Passed"
			ev.SignerSPC = "1186"
			ev.SignerName = "8x8, Inc."
			if listed {
				ev.Action = score.ActionReject
				ev.RiskScore = 100
				ev.Reasons = []score.Reason{
					{Code: "spam_feed_hit", Category: "feed", Weight: 100, Detail: "Calling number is on the CallerAPI spam feed"},
					{Code: "ip_intel_named", Category: "ipintel", Weight: 0, Detail: "Source IP belongs to 8x8, Inc., listed as trusted"},
				}
			} else {
				ev.Action = score.ActionAllow
				ev.RiskScore = 6
				ev.Reasons = []score.Reason{{Code: "ip_intel_named", Category: "ipintel", Weight: 0, Detail: "Source IP belongs to 8x8, Inc., listed as trusted"}}
			}
		} else {
			ev.Provider = "Datacenter"
			ev.Action = score.ActionFlag
			ev.RiskScore = 48
			ev.Reasons = []score.Reason{{Code: "ip_intel_suspicious", Category: "ipintel", Weight: 30, Detail: "Source IP belongs to Datacenter, listed as suspicious"}}
		}
	case "cpaas-zoom":
		if paid {
			ev.Provider = "Zoom Voice Communications, Inc."
			ev.Attest = "A"
			ev.Verstat = "TN-Validation-Passed"
			ev.SignerSPC = "1170"
			ev.SignerName = "Zoom Voice Communications, Inc."
			ev.Action = score.ActionAllow
			ev.RiskScore = 4
			ev.Reasons = []score.Reason{{Code: "ip_intel_named", Category: "ipintel", Weight: 0, Detail: "Source IP belongs to Zoom Voice Communications, Inc., listed as trusted"}}
		} else {
			ev.Provider = "Datacenter"
			ev.Action = score.ActionFlag
			ev.RiskScore = 44
			ev.Reasons = []score.Reason{{Code: "ip_intel_suspicious", Category: "ipintel", Weight: 30, Detail: "Source IP belongs to Datacenter, listed as suspicious"}}
		}
	case "gateway":
		if paid {
			ev.Provider = "Piratel llc"
			ev.Attest = "C"
			ev.Verstat = "TN-Validation-Passed"
			ev.SignerSPC = "1410"
			ev.SignerName = "Piratel llc"
			if listed {
				ev.Action = score.ActionReject
				ev.RiskScore = 100
				ev.Reasons = []score.Reason{{Code: "spam_feed_hit", Category: "feed", Weight: 100, Detail: "Calling number is on the CallerAPI spam feed"}}
			} else {
				ev.Action = score.ActionFlag
				ev.RiskScore = 38
				ev.Reasons = []score.Reason{{Code: "ip_intel_named", Category: "ipintel", Weight: 0, Detail: "Source IP belongs to Piratel llc, listed as neutral"}}
			}
		} else {
			ev.Action = score.ActionAllow
			ev.RiskScore = 12
			ev.Reasons = []score.Reason{{Code: "unsigned", Category: "shaken", Weight: 10, Detail: "No STIR/SHAKEN on the INVITE"}}
		}
	case "wholesale":
		if paid {
			ev.Provider = "9171-5573 Quebec Inc"
			ev.Action = score.ActionFlag
			ev.RiskScore = 42
			ev.Reasons = []score.Reason{{Code: "ip_intel_suspicious", Category: "ipintel", Weight: 30, Detail: "Source IP belongs to 9171-5573 Quebec Inc, listed as suspicious"}}
		} else {
			ev.Provider = "Datacenter"
			ev.Action = score.ActionFlag
			ev.RiskScore = 36
			ev.Reasons = []score.Reason{{Code: "ip_intel_suspicious", Category: "ipintel", Weight: 30, Detail: "Source IP belongs to Datacenter, listed as suspicious"}}
		}
	case "shared-gw":
		if paid {
			ev.Provider = "Versatel LLC"
			ev.Attest = "B"
			ev.Verstat = "TN-Validation-Passed"
			ev.SignerSPC = "1654"
			ev.SignerName = "Versatel LLC"
			ev.Action = score.ActionAllow
			ev.RiskScore = 14
			ev.Reasons = []score.Reason{{Code: "ip_intel_named", Category: "ipintel", Weight: 0, Detail: "Source IP belongs to Versatel LLC, listed as neutral"}}
		} else {
			ev.Action = score.ActionAllow
			ev.RiskScore = 10
		}
	case "junk", "spam":
		if paid {
			ev.Provider = "Unregistered cloud voice"
			ev.Action = score.ActionReject
			ev.RiskScore = 100
			ev.Reasons = []score.Reason{
				{Code: "ip_intel_block", Category: "ipintel", Weight: 100, Detail: "Source IP belongs to Unregistered cloud voice, listed as block"},
			}
			if listed {
				ev.Reasons = append(ev.Reasons, score.Reason{Code: "spam_feed_hit", Category: "feed", Weight: 100, Detail: "Calling number is on the CallerAPI spam feed"})
			}
		} else if raw.Kind == "junk" {
			ev.Provider = "VoIP abuse"
			ev.Action = score.ActionReject
			ev.RiskScore = 88
			ev.Reasons = []score.Reason{{Code: "ip_intel_block", Category: "ipintel", Weight: 100, Detail: "Source IP belongs to VoIP abuse, listed as block"}}
		} else {
			ev.Action = score.ActionAllow
			ev.RiskScore = 18
			ev.Reasons = []score.Reason{{Code: "unsigned", Category: "shaken", Weight: 10, Detail: "No STIR/SHAKEN on the INVITE"}}
		}
	default:
		ev.Action = score.ActionAllow
		ev.RiskScore = 4
	}
	if ev.Honeypot && ev.Action == score.ActionAllow {
		ev.Action = score.ActionFlag
		ev.RiskScore = 70
		ev.Reasons = append(ev.Reasons, score.Reason{Code: "honeypot", Category: "list", Weight: 60, Detail: "Called an unassigned number"})
	}
	return ev
}

// Main is falcon demo seed|swap.
func Main(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: falcon demo seed|swap free|paid")
	}
	dir := Dir("")
	switch args[0] {
	case "seed":
		if err := Seed(dir); err != nil {
			return err
		}
		fmt.Printf("seeded %s and %s\n", DBPath(dir, ProfileFree), DBPath(dir, ProfilePaid))
		return nil
	case "swap":
		if len(args) < 2 {
			return fmt.Errorf("usage: falcon demo swap free|paid")
		}
		profile, err := Normalize(args[1])
		if err != nil {
			return err
		}
		if !fileOK(DBPath(dir, profile)) {
			fmt.Println("seeding demo stores")
			if err := Seed(dir); err != nil {
				return err
			}
		}
		live := strings.TrimSpace(os.Getenv("FALCON_DB_PATH"))
		base := strings.TrimSpace(os.Getenv("FALCON_DEMO_URL"))
		if base == "" {
			base = "http://127.0.0.1:8090"
		}
		token := strings.TrimSpace(os.Getenv("FALCON_TOKEN"))
		if err := postSwap(base, token, profile); err == nil {
			fmt.Printf("swapped running Falcon to %s\n", profile)
			return nil
		}
		if live == "" {
			live = filepath.Join(dir, "live.db")
		}
		intel, err := Swap(dir, live, profile)
		if err != nil {
			return err
		}
		fmt.Printf("copied %s onto %s\nintel %s\nrestart Falcon with FALCON_DEMO=true FALCON_DEMO_PROFILE=%s FALCON_IP_INTEL_FILE=%s FALCON_DB_PATH=%s\n",
			DBPath(dir, profile), live, intel, profile, intel, live)
		return nil
	default:
		return fmt.Errorf("usage: falcon demo seed|swap free|paid")
	}
}

func postSwap(base, token, profile string) error {
	body := strings.NewReader(`{"profile":` + strconv.Quote(profile) + `}`)
	req, err := newDemoRequest(base+"/v1/demo", token, body)
	if err != nil {
		return err
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeSwap(resp)
}
