// Command falcon is CallerAPI Falcon: a local SIP risk engine with STIR/SHAKEN
// verification, telecom IP intel, operator lists, and a dashboard, in one
// binary next to the switch.
package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/callerapi/falcon/internal/alerts"
	"github.com/callerapi/falcon/internal/config"
	"github.com/callerapi/falcon/internal/demo"
	"github.com/callerapi/falcon/internal/export"
	"github.com/callerapi/falcon/internal/feed"
	"github.com/callerapi/falcon/internal/fleet"
	"github.com/callerapi/falcon/internal/httpapi"
	"github.com/callerapi/falcon/internal/identity"
	"github.com/callerapi/falcon/internal/ipintel"
	"github.com/callerapi/falcon/internal/plugin"
	"github.com/callerapi/falcon/internal/reputation"
	"github.com/callerapi/falcon/internal/score"
	"github.com/callerapi/falcon/internal/shaken"
	"github.com/callerapi/falcon/internal/sipserver"
	"github.com/callerapi/falcon/internal/store"
	"github.com/callerapi/falcon/internal/update"
	"github.com/callerapi/falcon/internal/voice"
)

// version is set with -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "demo" {
		if err := demo.Main(os.Args[2:]); err != nil {
			log.Fatalf("falcon demo: %v", err)
		}
		return
	}
	httpapi.Version = version
	cfg := config.Load()
	if cfg.Mode != config.ModeEnforce && cfg.Mode != config.ModeMonitor {
		log.Fatalf("falcon: FALCON_MODE must be enforce or monitor, got %q", cfg.Mode)
	}
	if cfg.FleetHub && strings.TrimSpace(cfg.FleetToken) == "" {
		log.Fatalf("falcon: FALCON_FLEET_HUB requires FALCON_FLEET_TOKEN")
	}
	if cfg.FleetURL != "" && strings.TrimSpace(cfg.FleetToken) == "" {
		log.Fatalf("falcon: FALCON_FLEET_URL requires FALCON_FLEET_TOKEN")
	}
	if cfg.FleetHub && cfg.FleetURL != "" {
		log.Printf("falcon fleet: this process is the hub, so FALCON_FLEET_URL is ignored")
		cfg.FleetURL = ""
	}
	if cfg.Demo {
		if err := prepareDemo(&cfg); err != nil {
			log.Fatalf("falcon demo: %v", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.OpenSQLite(cfg.DBPath)
	if err != nil {
		log.Fatalf("falcon store: %v", err)
	}
	defer db.Close()

	installID, err := ensureInstallID(ctx, db, cfg.InstallID)
	if err != nil {
		log.Fatalf("falcon install id: %v", err)
	}

	engine := score.NewEngine(
		score.Thresholds{Flag: cfg.FlagScore, Challenge: cfg.ChallengeScore, Reject: cfg.RejectScore},
		score.Limits{Window: cfg.VelocityWindow, IP: cfg.VelocityIP, From: cfg.VelocityFrom, Scan: cfg.VelocityScan, Fanout: cfg.FanoutPerHour, SequentialN: cfg.SequentialN},
	)

	var spam *feed.Spam
	if cfg.FeedEnabled() {
		spam = feed.NewSpam(cfg.CallerAPIBase, cfg.CallerAPIKey, cfg.FeedRefresh)
		go spam.Run(ctx)
	} else if cfg.Demo && cfg.DemoProfile == demo.ProfilePaid {
		spam = feed.NewSpam("", "demo", cfg.FeedRefresh)
		if nums, err := demo.SpamDIDs(cfg.DemoDir); err == nil {
			spam.LoadNumbers(nums)
		}
	}
	var live *feed.Live
	if cfg.FirewallEnabled() || cfg.BCIDEnabled() {
		live = &feed.Live{BaseURL: cfg.CallerAPIBase, APIKey: cfg.CallerAPIKey}
	}
	var ipTable *ipintel.Table
	if cfg.IPIntelEnabled() {
		ipTable = ipintel.New(cfg.IPIntelFile, cfg.IPIntelSource(), cfg.CallerAPIKey, cfg.IPIntelRefresh)
		go ipTable.Run(ctx)
	}
	var trust *shaken.TrustStore
	var verifier *shaken.Verifier
	if cfg.Shaken {
		trust = shaken.NewTrustStore(cfg.ShakenCAURL, cfg.ShakenCAFile, cfg.ShakenCRLURL)
		trust.ListPolicy = shaken.ListPolicy{Verify: cfg.ShakenVerifyList, PinSPKI: cfg.ShakenPAPin}
		if cfg.ShakenPARootFile != "" {
			pemBytes, err := os.ReadFile(cfg.ShakenPARootFile)
			if err != nil {
				log.Fatalf("falcon shaken: FALCON_SHAKEN_PA_ROOT_FILE: %v", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pemBytes) {
				log.Fatalf("falcon shaken: FALCON_SHAKEN_PA_ROOT_FILE holds no certificates")
			}
			trust.ListPolicy.Roots = pool
		}
		if !cfg.ShakenVerifyList {
			log.Printf("falcon shaken: WARNING FALCON_SHAKEN_VERIFY_LIST=false, the STI-PA CA list signature is not checked")
		}
		go trust.Run(ctx)
		opts := shaken.DefaultOptions()
		opts.Budget = cfg.ShakenBudget
		opts.AllowHTTP = cfg.ShakenAllowHTTP
		if opts.AllowHTTP {
			log.Printf("falcon: FALCON_SHAKEN_ALLOW_HTTP is on. Plain http x5u is accepted. Lab use only.")
		}
		verifier = shaken.New(trust, opts)
	}

	webFS, err := fs.Sub(httpapi.WebFS(), "web")
	if err != nil {
		log.Fatalf("falcon web: %v", err)
	}

	api := &httpapi.Server{
		Cfg:       cfg,
		Engine:    engine,
		Store:     db,
		Feed:      spam,
		Live:      live,
		IPIntel:   ipTable,
		Verifier:  verifier,
		Trust:     trust,
		Web:       webFS,
		InstallID: installID,
	}
	if err := api.Init(ctx); err != nil {
		log.Fatalf("falcon rules: %v", err)
	}

	q := &export.Queue{
		Store: db,
		S3: &export.S3{
			Endpoint:  cfg.S3Endpoint,
			Bucket:    cfg.S3Bucket,
			Region:    cfg.S3Region,
			AccessKey: cfg.S3AccessKey,
			SecretKey: cfg.S3SecretKey,
			Prefix:    cfg.S3Prefix + "/" + installID,
		},
		CallerAPIReady: api.Sharing,
	}
	installKey, err := identity.Load(ctx, db, installID)
	if err != nil {
		log.Fatalf("falcon identity: %v", err)
	}
	if cfg.Share {
		hmacKey, err := ensureSecret(ctx, db, "share_hmac_key")
		if err != nil {
			log.Fatalf("falcon share key: %v", err)
		}
		q.CallerAPI = &export.CallerAPI{
			BaseURL:   cfg.CallerAPIBase,
			APIKey:    cfg.CallerAPIKey,
			InstallID: installID,
			Version:   version,
			HMACKey:   hmacKey,
			Key:       installKey,
		}
		if cfg.Reputation {
			api.Reputation = &reputation.Table{
				BaseURL: cfg.CallerAPIBase,
				Key:     installKey,
				Refresh: cfg.ReputationRefresh,
				Enabled: api.Sharing,
			}
			go api.Reputation.Run(ctx)
		}
	}
	switch cfg.VoiceProvider {
	case "", "off":
	case "openai":
		if cfg.VoiceSTTAPIKey == "" && cfg.VoiceChatAPIKey == "" {
			log.Printf("falcon voice: FALCON_VOICE_PROVIDER=openai with no API key; a local server may not need one")
		}
		api.VoiceProvider = &voice.OpenAICompat{
			STTBaseURL: cfg.VoiceSTTBaseURL, STTAPIKey: cfg.VoiceSTTAPIKey, STTModel: cfg.VoiceSTTModel,
			ChatBaseURL: cfg.VoiceChatBaseURL, ChatAPIKey: cfg.VoiceChatAPIKey, ChatModel: cfg.VoiceChatModel,
		}
	case "callerapi":
		if cfg.CallerAPIKey == "" {
			log.Fatalf("falcon voice: FALCON_VOICE_PROVIDER=callerapi needs CALLERAPI_API_KEY")
		}
		api.VoiceProvider = &voice.CallerAPI{BaseURL: cfg.CallerAPIBase, APIKey: cfg.CallerAPIKey}
	default:
		log.Fatalf("falcon voice: unknown FALCON_VOICE_PROVIDER %q (off, openai, callerapi)", cfg.VoiceProvider)
	}
	api.VoiceReport = cfg.VoiceReport
	switch cfg.AssistantProvider {
	case "", "off":
	case "openai":
		api.Assistant = httpapi.AssistantConfig{Provider: "openai", BaseURL: cfg.AssistantBaseURL, APIKey: cfg.AssistantAPIKey, Model: cfg.AssistantModel}
	case "callerapi":
		if cfg.CallerAPIKey == "" {
			log.Fatalf("falcon assistant: FALCON_ASSISTANT_PROVIDER=callerapi needs CALLERAPI_API_KEY")
		}
		api.Assistant = httpapi.AssistantConfig{Provider: "callerapi", Model: "callerapi", CallerAPIBase: cfg.CallerAPIBase, CallerAPIKey: cfg.CallerAPIKey}
	default:
		log.Fatalf("falcon assistant: unknown FALCON_ASSISTANT_PROVIDER %q (off, openai, callerapi)", cfg.AssistantProvider)
	}
	api.Sampler = &voice.Sampler{
		Store:   db,
		Budget:  voice.Budget{PerHour: cfg.VoiceSamplesPerHour, PerCustomerPerHour: cfg.VoiceSamplesPerCust, ClipSeconds: cfg.VoiceClipSeconds},
		Enabled: api.VoiceProvider != nil || cfg.VoiceSampleWithoutAI,
	}
	if api.VoiceProvider != nil {
		log.Printf("falcon voice: provider %s, up to %d clips/hour, %d per customer, %d seconds each. Transcripts stay in %s.", api.VoiceProvider.Name(), cfg.VoiceSamplesPerHour, cfg.VoiceSamplesPerCust, cfg.VoiceClipSeconds, cfg.DBPath)
	} else if api.Sampler.Enabled {
		log.Printf("falcon voice: no provider; clips are still analysed on this host for repeat recordings and one-way monologues")
	}

	api.Alerts = &alerts.Watcher{Sources: alerts.Sources{
		Store:      db,
		Thresholds: api.AlertThresholds,
		TrustAge: func() (time.Duration, bool) {
			if trust == nil || !trust.Enabled() {
				return 0, false
			}
			st := trust.Status()
			if st.RootsAt.IsZero() {
				return 0, false
			}
			return time.Since(st.RootsAt), true
		},
		Version:   version,
		InstallID: installID,
	}}
	go api.Alerts.Run(ctx)
	if cfg.Mode == config.ModeMonitor {
		log.Printf("falcon mode: monitor. Decisions are recorded. The switch is told to continue.")
	}
	if cfg.FleetURL != "" {
		cache := fleet.NewCache(2 * cfg.FleetInterval)
		api.Fleet = cache
		go (&fleet.Member{
			URL: cfg.FleetURL, Token: cfg.FleetToken, InstallID: installID,
			Interval: cfg.FleetInterval, Store: db, Cache: cache, Reload: api.ReloadRules,
		}).Run(ctx)
		log.Printf("falcon fleet: member of %s", cfg.FleetURL)
	}
	if cfg.FleetHub {
		log.Printf("falcon fleet: hub on /v1/fleet")
	}
	if cfg.Plugins && cfg.CallerAPIKey != "" {
		plugins := plugin.New(cfg.CallerAPIBase, cfg.CallerAPIKey, cfg.PluginRefresh, cfg.PluginBudget)
		api.Plugins = plugins
		go plugins.Run(ctx)
		log.Printf("falcon plugins: catalog from %s every %s, live budget %s", cfg.CallerAPIBase, cfg.PluginRefresh, cfg.PluginBudget)
	}
	if cfg.UpdateCheck {
		go (&update.Checker{
			Version: version, Interval: cfg.UpdateInterval, Alerts: api.Alerts, Store: db,
			OnStatus: api.SetRelease,
		}).Run(ctx)
	}
	logSharing(ctx, api)
	go q.Run(ctx)
	go store.Janitor(ctx, db, api.Retention)

	if cfg.Token == "" {
		if !cfg.ListensOnLoopback() && !cfg.AllowOpen {
			log.Fatalf("falcon: FALCON_TOKEN is empty and FALCON_LISTEN=%s is not loopback. Set a token, or set FALCON_ALLOW_OPEN=true if a firewall in front of this host is the only thing you want.", cfg.Listen)
		}
		log.Printf("falcon: FALCON_TOKEN is empty. Switch API is open on %s.", cfg.Listen)
	}
	if cfg.MaxBody > 0 {
		httpapi.MaxBody = cfg.MaxBody
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: /v1/stream holds a response open on purpose.
		MaxHeaderBytes: 64 * 1024,
	}
	go func() {
		log.Printf("falcon %s listening on %s (profile=%s, dashboard /, screen POST /v1/screen, shaken=%v ipintel=%v)", version, cfg.Listen, cfg.Profile, cfg.Shaken, cfg.IPIntelEnabled())
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("falcon http: %v", err)
		}
	}()

	if cfg.SIPEnabled() {
		startSIP(ctx, cfg, api)
	}

	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}

// startSIP binds the SIP redirect listener. A non-loopback listen with no
// peer allowlist is refused: SIP has no token, so the allowlist is the
// only gate.
func startSIP(ctx context.Context, cfg config.Config, api *httpapi.Server) {
	peers, err := sipserver.ParsePeers(cfg.SIPPeers)
	if err != nil {
		log.Fatalf("falcon sip: %v", err)
	}
	if len(peers) == 0 && !cfg.SIPListensOnLoopback() {
		log.Fatalf("falcon sip: FALCON_SIP_LISTEN=%s is not loopback and FALCON_SIP_PEERS is empty. List the switch IPs or CIDRs that may send INVITEs.", cfg.SIPListen)
	}
	sip, err := sipserver.New(sipserver.Config{
		Listen:       cfg.SIPListen,
		Peers:        peers,
		RedirectHost: cfg.SIPRedirectHost,
		Timeout:      cfg.SIPTimeout,
		Version:      version,
	}, api)
	if err != nil {
		log.Fatalf("falcon sip: %v", err)
	}
	go func() {
		log.Printf("falcon sip redirect listening on %s (udp+tcp, peers=%d, 302 continue / 603 reject)", cfg.SIPListen, len(peers))
		_ = sip.Serve(ctx)
	}()
}

// logSharing prints the telemetry state on every boot so nobody learns
// about it from a network capture.
func logSharing(ctx context.Context, api *httpapi.Server) {
	st := api.Settings(ctx)
	switch {
	case !api.Cfg.Share:
		log.Printf("falcon telemetry: off (FALCON_SHARE=false)")
	case !st.ShareTelemetry:
		log.Printf("falcon telemetry: off (opted out in the dashboard)")
	default:
		log.Printf("falcon telemetry: on. Redacted screening events go to %s every 30s. Called numbers, forwarding numbers, the PASSporT, and SDP are removed before send. Opt out with FALCON_SHARE=false or in the System view.", api.Cfg.CallerAPIBase+export.Endpoint)
	}
}

// ensureSecret returns a stored random secret, creating it on first use.
func ensureSecret(ctx context.Context, db store.Store, key string) ([]byte, error) {
	existing, err := db.KVGet(ctx, key)
	if err != nil {
		return nil, err
	}
	if existing != "" {
		return hex.DecodeString(existing)
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return b[:], db.KVSet(ctx, key, hex.EncodeToString(b[:]))
}

func prepareDemo(cfg *config.Config) error {
	dir := demo.Dir(cfg.DemoDir)
	cfg.DemoDir = dir
	profile, err := demo.Normalize(cfg.DemoProfile)
	if err != nil {
		profile = demo.ProfileFree
	}
	cfg.DemoProfile = profile
	if _, err := os.Stat(demo.DBPath(dir, profile)); err != nil {
		log.Printf("falcon demo: seeding %s", dir)
		if err := demo.Seed(dir); err != nil {
			return err
		}
	}
	if cfg.IPIntelFile == "" {
		cfg.IPIntelFile = demo.IntelPath(dir, profile)
	}
	if _, err := os.Stat(cfg.DBPath); err != nil {
		if _, err := demo.Swap(dir, cfg.DBPath, profile); err != nil {
			return err
		}
	}
	return nil
}

func ensureInstallID(ctx context.Context, db store.Store, configured string) (string, error) {
	if configured != "" {
		return configured, db.KVSet(ctx, "install_id", configured)
	}
	existing, err := db.KVGet(ctx, "install_id")
	if err != nil {
		return "", err
	}
	if existing != "" {
		return existing, nil
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b[:])
	return id, db.KVSet(ctx, "install_id", id)
}
