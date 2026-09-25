package config

import (
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is process configuration from the environment.
type Config struct {
	Profile string
	Listen  string
	Token   string
	// MetricsToken is the credential Prometheus sends to GET /metrics.
	// Empty means /metrics accepts Token.
	MetricsToken string
	// Mode is enforce (default) or monitor. Monitor records the decision
	// and tells the switch to continue.
	Mode string
	// UpdateCheck compares this build with the public Falcon release.
	UpdateCheck    bool
	UpdateInterval time.Duration
	// FleetHub accepts events and serves rules for other Falcons.
	// FleetURL is the hub those nodes push to. A hub leaves FleetURL empty.
	FleetHub          bool
	FleetURL          string
	FleetToken        string
	FleetInterval     time.Duration
	Plugins           bool
	PluginRefresh     time.Duration
	PluginBudget      time.Duration
	DashboardUser     string
	DashboardPassword string
	DBPath            string
	InstallID         string
	FailOpen          bool

	FlagScore      int
	ChallengeScore int
	RejectScore    int

	VelocityWindow time.Duration
	VelocityIP     int
	VelocityFrom   int
	VelocityScan   int

	S3Endpoint  string
	S3Bucket    string
	S3Region    string
	S3AccessKey string
	S3SecretKey string
	S3Prefix    string

	CallerAPIKey  string
	CallerAPIBase string
	SpamFeed      bool
	VoiceFirewall bool
	// BCID verifies each INVITE against CallerAPI Business Caller ID.
	// On by default when a key is present. Verify is free for the telco.
	BCID bool
	// Share sends redacted screening events to CallerAPI. On by default.
	// The called party never leaves the host; see internal/share.
	Share       bool
	FeedRefresh time.Duration
	// Reputation pulls the network feed built from sharing installs and
	// scores signers and tools with it. ReputationEnforce lets a strong
	// signer score reject on its own; off by default.
	Reputation        bool
	ReputationEnforce bool
	ReputationRefresh time.Duration

	// Behaviour thresholds over the last hour; zero means the default.
	FanoutPerHour int
	SequentialN   int

	// Voice analysis. Provider is off, openai (any OpenAI-compatible pair
	// of speech and chat endpoints), or callerapi (the scan API on the
	// account key). Clips are taken only on a trigger and within a budget.
	VoiceProvider        string
	VoiceSTTBaseURL      string
	VoiceSTTAPIKey       string
	VoiceSTTModel        string
	VoiceChatBaseURL     string
	VoiceChatAPIKey      string
	VoiceChatModel       string
	VoiceReport          bool
	VoiceSamplesPerHour  int
	VoiceSamplesPerCust  int
	VoiceClipSeconds     int
	VoiceSampleWithoutAI bool

	// Assistant: the chat model behind "Ask Falcon". off, openai (any
	// OpenAI-compatible chat endpoint, defaults to the voice chat settings),
	// or callerapi (on CALLERAPI_API_KEY). The value card needs none.
	AssistantProvider string
	AssistantBaseURL  string
	AssistantAPIKey   string
	AssistantModel    string

	// IP intel: a CIDR table of telecom providers and their risk. A local
	// file, a URL, or both. IPIntel turns on the hosted CallerAPI table when
	// a key is present and no URL is given.
	IPIntel        bool
	IPIntelFile    string
	IPIntelURL     string
	IPIntelRefresh time.Duration

	// STIR/SHAKEN verification. On by default. The trust list and CRL come
	// from the public STI-PA endpoints unless a file or another URL is set.
	Shaken       bool
	ShakenCAURL  string
	ShakenCAFile string
	ShakenCRLURL string
	// ShakenBudget is how long one screen waits for a cold certificate.
	ShakenBudget time.Duration
	// ShakenVerifyList checks the STI-PA CA list JWS signature, expiry, and
	// sequence. ShakenPAPin pins the list-signing key (base64 SHA-256 of
	// its SPKI). ShakenPARootFile is the STI-PA root PEM to chain to.
	ShakenVerifyList bool
	ShakenPAPin      string
	ShakenPARootFile string
	// ShakenAllowHTTP accepts plain http x5u URLs. Lab rigs only.
	ShakenAllowHTTP bool

	// RetentionDays is how long events stay in the local database.
	RetentionDays int
	// RawSIPRetentionDays is how long the raw SIP message is kept on an
	// event before it is scrubbed. The scored row stays. Raw SIP carries
	// subscriber numbers and should live shorter than the decision.
	RawSIPRetentionDays int
	// StoreRawSIP false never writes the raw message at all.
	StoreRawSIP bool

	// AllowOpen permits an empty token on a non-loopback listen. Off by
	// default: an open Falcon on a public interface is a mistake.
	AllowOpen bool
	// MaxBody caps one screened SIP message in bytes.
	MaxBody int64

	// SIPListen turns on the SIP redirect listener (UDP and TCP) for
	// switches with no script hook. Empty is off. SIPPeers is the list of
	// IPs and CIDRs that may send to it. SIPRedirectHost rewrites the host
	// in the Contact of a 302; empty echoes the Request-URI.
	SIPListen       string
	SIPPeers        string
	SIPRedirectHost string
	SIPTimeout      time.Duration

	UpsellFeedURL     string
	UpsellFirewallURL string

	// Demo enables the Zoom profile swap (POST /v1/demo and falcon demo).
	Demo        bool
	DemoDir     string
	DemoProfile string
}

// Profile names a set of defaults for where Falcon sits.
//
//	trunk    The default. An inbound trunk into a PBX or an enterprise. Per-IP
//	         and per-CLI velocity rules catch scanners. Scores reject.
//	carrier  A class 4 or wholesale ingress. One customer IP sends hundreds of
//	         calls a minute and one CLI reaches thousands of numbers. Velocity
//	         rules are off and scores only flag. Hard blocks still reject: deny
//	         rules, the spam feed, IP intel block rows, and a caller id the
//	         customer does not own.
//
// Every value a profile sets is still overridden by its own variable.
const (
	ProfileTrunk   = "trunk"
	ProfileCarrier = "carrier"

	ModeEnforce = "enforce"
	ModeMonitor = "monitor"
)

func Load() Config {
	profile := strings.ToLower(env("FALCON_PROFILE", ProfileTrunk))
	challenge, reject := 60, 80
	velIP, velFrom, velScan := 30, 20, 15
	if profile == ProfileCarrier {
		// 101 is above the 100 cap, so a score alone never reaches it.
		challenge, reject = 101, 101
		velIP, velFrom, velScan = 0, 0, 0
	}
	return Config{
		Profile:           profile,
		Listen:            env("FALCON_LISTEN", "127.0.0.1:8090"),
		Token:             env("FALCON_TOKEN", ""),
		MetricsToken:      env("FALCON_METRICS_TOKEN", ""),
		Mode:              strings.ToLower(env("FALCON_MODE", ModeEnforce)),
		UpdateCheck:       envBool("FALCON_UPDATE_CHECK", true),
		UpdateInterval:    envDuration("FALCON_UPDATE_INTERVAL", 6*time.Hour),
		FleetHub:          envBool("FALCON_FLEET_HUB", false),
		FleetURL:          strings.TrimRight(env("FALCON_FLEET_URL", ""), "/"),
		FleetToken:        env("FALCON_FLEET_TOKEN", ""),
		FleetInterval:     envDuration("FALCON_FLEET_INTERVAL", 30*time.Second),
		Plugins:           envBool("FALCON_PLUGINS", true),
		PluginRefresh:     envDuration("FALCON_PLUGIN_REFRESH", time.Minute),
		PluginBudget:      envDuration("FALCON_PLUGIN_BUDGET", 400*time.Millisecond),
		DashboardUser:     env("FALCON_DASHBOARD_USER", "admin"),
		DashboardPassword: env("FALCON_DASHBOARD_PASSWORD", ""),
		DBPath:            env("FALCON_DB_PATH", "./data/falcon.db"),
		InstallID:         env("FALCON_INSTALL_ID", ""),
		FailOpen:          envBool("FALCON_FAIL_OPEN", true),

		FlagScore:      envInt("FALCON_FLAG_SCORE", 40),
		ChallengeScore: envInt("FALCON_CHALLENGE_SCORE", challenge),
		RejectScore:    envInt("FALCON_REJECT_SCORE", reject),

		VelocityWindow: envDuration("FALCON_VELOCITY_WINDOW", 60*time.Second),
		VelocityIP:     envInt("FALCON_VELOCITY_IP", velIP),
		VelocityFrom:   envInt("FALCON_VELOCITY_FROM", velFrom),
		VelocityScan:   envInt("FALCON_VELOCITY_SCAN", velScan),

		S3Endpoint:  env("FALCON_S3_ENDPOINT", ""),
		S3Bucket:    env("FALCON_S3_BUCKET", ""),
		S3Region:    env("FALCON_S3_REGION", "auto"),
		S3AccessKey: env("FALCON_S3_ACCESS_KEY", ""),
		S3SecretKey: env("FALCON_S3_SECRET_KEY", ""),
		S3Prefix:    env("FALCON_S3_PREFIX", "falcon"),

		CallerAPIKey:  firstNonEmpty(os.Getenv("CALLERAPI_API_KEY"), os.Getenv("FALCON_CALLERAPI_KEY")),
		CallerAPIBase: strings.TrimRight(env("CALLERAPI_API_BASE", "https://api.callerapi.com"), "/"),
		SpamFeed:      envBool("FALCON_SPAM_FEED", false),
		VoiceFirewall: envBool("FALCON_VOICE_FIREWALL", false),
		BCID:          envBool("FALCON_BCID", true),
		Share:         envBool("FALCON_SHARE", true),
		FanoutPerHour: envInt("FALCON_FANOUT_PER_HOUR", 30),
		SequentialN:   envInt("FALCON_SEQUENTIAL_N", 5),

		VoiceProvider:        strings.ToLower(env("FALCON_VOICE_PROVIDER", "off")),
		VoiceSTTBaseURL:      strings.TrimRight(env("FALCON_VOICE_STT_BASE_URL", "https://api.openai.com/v1"), "/"),
		VoiceSTTAPIKey:       env("FALCON_VOICE_STT_API_KEY", ""),
		VoiceSTTModel:        env("FALCON_VOICE_STT_MODEL", "whisper-1"),
		VoiceChatBaseURL:     strings.TrimRight(firstNonEmpty(os.Getenv("FALCON_VOICE_CHAT_BASE_URL"), os.Getenv("FALCON_VOICE_STT_BASE_URL"), "https://api.openai.com/v1"), "/"),
		VoiceChatAPIKey:      firstNonEmpty(os.Getenv("FALCON_VOICE_CHAT_API_KEY"), os.Getenv("FALCON_VOICE_STT_API_KEY")),
		VoiceChatModel:       env("FALCON_VOICE_CHAT_MODEL", "gpt-4o-mini"),
		VoiceReport:          envBool("FALCON_VOICE_REPORT", true),
		VoiceSamplesPerHour:  envInt("FALCON_VOICE_SAMPLES_PER_HOUR", 60),
		VoiceSamplesPerCust:  envInt("FALCON_VOICE_SAMPLES_PER_CUSTOMER_HOUR", 10),
		VoiceClipSeconds:     envInt("FALCON_VOICE_CLIP_SECONDS", 20),
		VoiceSampleWithoutAI: envBool("FALCON_VOICE_SAMPLE_WITHOUT_AI", true),

		AssistantProvider: strings.ToLower(env("FALCON_ASSISTANT_PROVIDER", "off")),
		AssistantBaseURL:  strings.TrimRight(firstNonEmpty(os.Getenv("FALCON_ASSISTANT_BASE_URL"), os.Getenv("FALCON_VOICE_CHAT_BASE_URL"), os.Getenv("FALCON_VOICE_STT_BASE_URL"), "https://api.openai.com/v1"), "/"),
		AssistantAPIKey:   firstNonEmpty(os.Getenv("FALCON_ASSISTANT_API_KEY"), os.Getenv("FALCON_VOICE_CHAT_API_KEY"), os.Getenv("FALCON_VOICE_STT_API_KEY")),
		AssistantModel:    firstNonEmpty(os.Getenv("FALCON_ASSISTANT_MODEL"), os.Getenv("FALCON_VOICE_CHAT_MODEL"), "gpt-4o-mini"),

		Reputation:        envBool("FALCON_REPUTATION", true),
		ReputationEnforce: envBool("FALCON_REPUTATION_ENFORCE", false),
		ReputationRefresh: envDuration("FALCON_REPUTATION_REFRESH", time.Hour),
		FeedRefresh:       envDuration("FALCON_FEED_REFRESH", time.Hour),

		IPIntel:        envBool("FALCON_IP_INTEL", false),
		IPIntelFile:    env("FALCON_IP_INTEL_FILE", ""),
		IPIntelURL:     env("FALCON_IP_INTEL_URL", ""),
		IPIntelRefresh: envDuration("FALCON_IP_INTEL_REFRESH", time.Hour),

		Shaken:           envBool("FALCON_SHAKEN", true),
		ShakenCAURL:      envURL("FALCON_SHAKEN_CA_URL", "https://authenticate-api.iconectiv.com/api/v1/ca-list"),
		ShakenCAFile:     env("FALCON_SHAKEN_CA_FILE", ""),
		ShakenCRLURL:     envURL("FALCON_SHAKEN_CRL_URL", "https://authenticate-api.iconectiv.com/download/v1/crl"),
		ShakenBudget:     envDuration("FALCON_SHAKEN_BUDGET", 400*time.Millisecond),
		ShakenAllowHTTP:  envBool("FALCON_SHAKEN_ALLOW_HTTP", false),
		ShakenVerifyList: envBool("FALCON_SHAKEN_VERIFY_LIST", true),
		ShakenPAPin:      env("FALCON_SHAKEN_PA_PIN", ""),
		ShakenPARootFile: env("FALCON_SHAKEN_PA_ROOT_FILE", ""),

		RetentionDays:       envInt("FALCON_RETENTION_DAYS", 30),
		RawSIPRetentionDays: envInt("FALCON_RAW_SIP_RETENTION_DAYS", 7),
		StoreRawSIP:         envBool("FALCON_STORE_RAW_SIP", true),
		AllowOpen:           envBool("FALCON_ALLOW_OPEN", false),
		MaxBody:             int64(envInt("FALCON_MAX_BODY_BYTES", 64*1024)),

		SIPListen:       env("FALCON_SIP_LISTEN", ""),
		SIPPeers:        env("FALCON_SIP_PEERS", ""),
		SIPRedirectHost: env("FALCON_SIP_REDIRECT_HOST", ""),
		SIPTimeout:      envDuration("FALCON_SIP_TIMEOUT", 2*time.Second),

		UpsellFeedURL:     env("FALCON_UPSELL_FEED_URL", "https://callerapi.com"),
		UpsellFirewallURL: env("FALCON_UPSELL_FIREWALL_URL", "https://callerapi.com/sip-firewall"),

		Demo:        envBool("FALCON_DEMO", false),
		DemoDir:     env("FALCON_DEMO_DIR", ""),
		DemoProfile: env("FALCON_DEMO_PROFILE", "free"),
	}
}

func (c Config) S3Enabled() bool {
	return c.S3Endpoint != "" && c.S3Bucket != "" && c.S3AccessKey != "" && c.S3SecretKey != ""
}

func (c Config) FeedEnabled() bool {
	return c.SpamFeed && c.CallerAPIKey != ""
}

func (c Config) FirewallEnabled() bool {
	return c.VoiceFirewall && c.CallerAPIKey != ""
}

func (c Config) BCIDEnabled() bool {
	return c.BCID && c.CallerAPIKey != ""
}

// IPIntelSource returns the URL the table loads from. An explicit URL wins.
// Otherwise the hosted CallerAPI table is used when IPIntel is on and a key
// is present. Empty means no remote source.
func (c Config) IPIntelSource() string {
	if c.IPIntelURL != "" {
		return c.IPIntelURL
	}
	if c.IPIntel && c.CallerAPIKey != "" {
		return c.CallerAPIBase + "/api/ip-intel/v1/list.csv"
	}
	return ""
}

// IPIntelEnabled reports whether any IP intel source is configured.
func (c Config) IPIntelEnabled() bool {
	return c.IPIntelFile != "" || c.IPIntelSource() != ""
}

// ListensOnLoopback reports whether the listen address is local only.
func (c Config) ListensOnLoopback() bool {
	return addrIsLoopback(c.Listen)
}

// SIPEnabled reports whether the SIP redirect listener is on.
func (c Config) SIPEnabled() bool {
	return strings.TrimSpace(c.SIPListen) != ""
}

// SIPListensOnLoopback reports whether the SIP listener is local only.
func (c Config) SIPListensOnLoopback() bool {
	return addrIsLoopback(c.SIPListen)
}

func addrIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// Redacted is the configuration as the dashboard may show it. Secrets are
// replaced by whether they are set.
func (c Config) Redacted() map[string]any {
	set := func(v string) string {
		if strings.TrimSpace(v) == "" {
			return ""
		}
		return "set"
	}
	return map[string]any{
		"profile":            c.Profile,
		"listen":             c.Listen,
		"token":              set(c.Token),
		"metrics_token":      set(c.MetricsToken),
		"mode":               c.Mode,
		"update_check":       c.UpdateCheck,
		"fleet":              map[string]any{"hub": c.FleetHub, "url": c.FleetURL, "token": set(c.FleetToken), "interval": c.FleetInterval.String()},
		"plugins":            map[string]any{"enabled": c.Plugins && c.CallerAPIKey != "", "refresh": c.PluginRefresh.String(), "budget": c.PluginBudget.String()},
		"dashboard_user":     c.DashboardUser,
		"dashboard_password": set(c.DashboardPassword),
		"db_path":            c.DBPath,
		"fail_open":          c.FailOpen,
		"thresholds":         map[string]int{"flag": c.FlagScore, "challenge": c.ChallengeScore, "reject": c.RejectScore},
		"velocity":           map[string]any{"window": c.VelocityWindow.String(), "ip": c.VelocityIP, "from": c.VelocityFrom, "scan": c.VelocityScan},
		"s3":                 map[string]any{"enabled": c.S3Enabled(), "endpoint": c.S3Endpoint, "bucket": c.S3Bucket, "prefix": c.S3Prefix},
		"callerapi": map[string]any{"base": c.CallerAPIBase, "key": set(c.CallerAPIKey), "spam_feed": c.FeedEnabled(), "voice_firewall": c.FirewallEnabled(), "bcid": c.BCIDEnabled(), "share": c.Share, "reputation": c.Reputation, "reputation_enforce": c.ReputationEnforce,
			"voice":     map[string]any{"provider": c.VoiceProvider, "stt_base": c.VoiceSTTBaseURL, "stt_model": c.VoiceSTTModel, "stt_key": set(c.VoiceSTTAPIKey), "chat_base": c.VoiceChatBaseURL, "chat_model": c.VoiceChatModel, "chat_key": set(c.VoiceChatAPIKey), "report": c.VoiceReport, "samples_per_hour": c.VoiceSamplesPerHour, "samples_per_customer_hour": c.VoiceSamplesPerCust, "clip_seconds": c.VoiceClipSeconds, "sample_without_ai": c.VoiceSampleWithoutAI},
			"assistant": map[string]any{"provider": c.AssistantProvider, "base": c.AssistantBaseURL, "model": c.AssistantModel, "key": set(c.AssistantAPIKey)},
			"behaviour": map[string]any{"fanout_per_hour": c.FanoutPerHour, "sequential_n": c.SequentialN}, "feed_refresh": c.FeedRefresh.String()},
		"ip_intel":       map[string]any{"enabled": c.IPIntelEnabled(), "file": c.IPIntelFile, "url": c.IPIntelSource(), "refresh": c.IPIntelRefresh.String()},
		"demo":           map[string]any{"enabled": c.Demo, "dir": c.DemoDir, "profile": c.DemoProfile},
		"shaken":         map[string]any{"enabled": c.Shaken, "ca_url": c.ShakenCAURL, "ca_file": c.ShakenCAFile, "crl_url": c.ShakenCRLURL, "budget": c.ShakenBudget.String(), "allow_http": c.ShakenAllowHTTP, "verify_list": c.ShakenVerifyList, "pa_pin": set(c.ShakenPAPin), "pa_root_file": c.ShakenPARootFile},
		"retention_days": c.RetentionDays,
		"raw_sip":        map[string]any{"stored": c.StoreRawSIP, "retention_days": c.RawSIPRetentionDays},
		"allow_open":     c.AllowOpen,
		"max_body_bytes": c.MaxBody,
		"sip":            map[string]any{"enabled": c.SIPEnabled(), "listen": c.SIPListen, "peers": c.SIPPeers, "redirect_host": c.SIPRedirectHost, "timeout": c.SIPTimeout.String()},
	}
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// envURL is env with an off switch: "off" or "none" disables a default URL,
// which an air-gapped install needs.
func envURL(key, fallback string) string {
	v := env(key, fallback)
	switch strings.ToLower(v) {
	case "off", "none", "disabled":
		return ""
	}
	return v
}

func envBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func envInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
