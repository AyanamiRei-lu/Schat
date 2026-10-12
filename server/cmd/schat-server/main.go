// Command schat-server is the SCHAT relay.
//
// It forwards opaque, end-to-end encrypted envelopes between clients. It holds no
// database, writes no user data to disk, and contains no code capable of reading
// an envelope, so it cannot see what it carries even if it is fully compromised.
// See SCHAT.md sections 7 and 8 for the design and docs/SERVER-SETUP.md for
// deployment.
//
// Usage:
//
//	schat-server                                     # zero configuration
//	schat-server --public-host 192.168.1.158          # LAN
//	schat-server --listen 0.0.0.0:8443 --mode buffer  # hold messages briefly
//	schat-server --cert-file cert.pem --key-file key.pem
//	schat-server --print-uri                          # emit the client URI and exit
//
// TLS note: this server does NOT obtain Let's Encrypt certificates. Doing so would
// require golang.org/x/crypto/acme/autocert, which would give the server module its
// first third-party dependency and break the mechanical supply-chain guarantee in
// server/go.mod. Public deployments terminate TLS at a reverse proxy; see the
// tlsutil package comment.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/schat/schat/server/internal/config"
	"github.com/schat/schat/server/internal/directory"
	"github.com/schat/schat/server/internal/gateway"
	"github.com/schat/schat/server/internal/metrics"
	"github.com/schat/schat/server/internal/queue"
	"github.com/schat/schat/server/internal/router"
	"github.com/schat/schat/server/internal/tlsutil"
	"github.com/schat/schat/server/internal/version"
)

// shutdownGrace is how long in-flight requests get to finish on SIGTERM.
const shutdownGrace = 10 * time.Second

// sweepInterval is how often expired buffered envelopes are reclaimed.
const sweepInterval = time.Minute

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "schat-server: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("schat-server", flag.ContinueOnError)

	var (
		configPath   = fs.String("config", "", "path to a JSON configuration file (optional)")
		listen       = fs.String("listen", "", "public listen address, host:port")
		publicHost   = fs.String("public-host", "", "host or IP clients should dial; use this for LAN testing, e.g. 192.168.1.158")
		domain       = fs.String("domain", "", "public domain name (implies --public-host; see the TLS note below)")
		name         = fs.String("name", "", "friendly server name shown in the client")
		mode         = fs.String("mode", "", "delivery mode: live (default, stores nothing) or buffer")
		metricsAddr  = fs.String("metrics-listen", "", "address for the metrics endpoint, host:port")
		logLevel     = fs.String("log-level", "", "log level: debug, info, warn or error")
		stateDir     = fs.String("state-dir", "", "directory holding the persistent self-signed certificate (default: the user cache directory)")
		noTLS        = fs.Bool("no-tls", false, "serve plaintext HTTP; for local debugging only")
		printVersion = fs.Bool("version", false, "print the build identity and exit")
		printURI     = fs.Bool("print-uri", false, "print the client connection URI and exit")
	)

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "schat-server %s — SCHAT relay server\n\n", version.Version)
		fmt.Fprintf(os.Stderr, "Usage:\n  schat-server [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nTLS: the server generates a persistent self-signed certificate by default\n"+
			"and prints its fingerprint for clients to pin. It does NOT obtain Let's Encrypt\n"+
			"certificates; terminate public TLS at a reverse proxy, or supply --cert-file and\n"+
			"--key-file.\n")
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	if *printVersion {
		fmt.Println(version.String())
		return nil
	}

	// Start from defaults, layer the optional configuration file on top, then apply
	// only the flags the operator actually typed, so that a configuration file is
	// never silently overridden by a default and a flag always wins over the file.
	cfg := config.Default()
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		cfg = loaded
	}

	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	if explicit["listen"] {
		cfg.Listen = *listen
	}
	if explicit["public-host"] {
		cfg.PublicHost = *publicHost
	}
	if explicit["domain"] {
		// --domain no longer means "obtain a certificate for this name": this server
		// does not talk to an ACME server. It now means "this is the name clients
		// dial", and any certificate comes from --cert-file/--key-file or the
		// reverse proxy in front.
		cfg.PublicHost = *domain
		cfg.TLS.Domain = *domain
	}
	if explicit["name"] {
		cfg.Name = *name
	}
	if explicit["mode"] {
		cfg.Mode = config.Mode(*mode)
	}
	if explicit["metrics-listen"] {
		cfg.MetricsListen = *metricsAddr
	}
	if explicit["log-level"] {
		cfg.Log.Level = *logLevel
	}
	if !explicit["state-dir"] {
		*stateDir = defaultStateDir()
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	log := newLogger(cfg)
	counters := metrics.New()

	// ---- Transport ----------------------------------------------------------
	var (
		tlsConfig   *tls.Config
		fingerprint string
	)

	if !*noTLS {
		conf, fp, err := buildTLS(cfg, *stateDir, log)
		if err != nil {
			return err
		}
		tlsConfig, fingerprint = conf, fp
	}

	if *printURI {
		fmt.Println(cfg.ConnectURI(fingerprint))
		return nil
	}

	printBanner(cfg, *stateDir, fingerprint, *noTLS, log)

	// ---- Relay state --------------------------------------------------------
	// In live mode nothing is ever held, so there is no queue at all rather than one
	// that happens to be unused. A type that does not exist cannot leak.
	var q *queue.Queue
	if cfg.Mode == config.ModeBuffer {
		var err error
		q, err = queue.New(cfg.Buffer.MaxPerToken, cfg.Buffer.TTL, cfg.Buffer.MaxGlobalMemory)
		if err != nil {
			return fmt.Errorf("buffer mode: %w", err)
		}
		log.Info("buffer mode enabled: envelopes are held in RAM only and are lost on restart",
			"ttl", cfg.Buffer.TTL,
			"max_per_mailbox", cfg.Buffer.MaxPerToken,
			"max_memory", cfg.Buffer.MaxGlobalMemory)
	} else {
		log.Info("live mode: nothing is stored; an offline recipient's message is refused, not queued")
	}

	r := router.New()
	gw := gateway.New(cfg, r, q, counters, log)

	// The prekey directory holds only public key material, for the same lifetime as
	// everything else the relay keeps: until the process stops. It is what lets two
	// peers who have never spoken find each other's keys (SCHAT.md section 4.4).
	keys, err := directory.New(directory.DefaultTTL, directory.DefaultMaxIdentities)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", gw.ServeWS)
	mux.HandleFunc("/api/v1/health", healthHandler(cfg, counters, gw, keys, fingerprint))
	mux.HandleFunc("/api/v1/config", publicConfigHandler(cfg, fingerprint))
	mux.Handle("/api/v1/keys/", keys)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConfig,

		// A WebSocket upgrade works by hijacking the connection, which HTTP/2 does
		// not permit. Installing an empty TLSNextProto map disables HTTP/2 entirely
		// so that a client cannot negotiate a protocol on which /ws could never
		// succeed, and then report a confusing failure.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Metrics live on a separate, loopback-by-default listener so that queue depth
	// and connection counts are not exposed publicly.
	var metricsSrv *http.Server
	if cfg.MetricsListen != "" {
		metricsMux := http.NewServeMux()
		metricsMux.HandleFunc("/metrics", metricsHandler(counters, r, q, gw))
		metricsSrv = &http.Server{
			Addr:              cfg.MetricsListen,
			Handler:           metricsMux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			log.Info("metrics endpoint listening", "addr", cfg.MetricsListen)
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics listener failed", "err", err)
			}
		}()
	}

	if q != nil {
		go sweepLoop(ctx, q, log)
	}

	errCh := make(chan error, 1)
	go func() {
		if *noTLS {
			log.Warn("TLS is DISABLED: envelopes are still end-to-end encrypted, but message " +
				"sizes, timings and delivery tokens are visible to anyone on the network. " +
				"Use this only for local debugging.")
			log.Info("relay listening (plaintext)", "addr", cfg.Listen)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
			return
		}
		// The floor is TLS 1.2 rather than 1.3 because Android 8/9 (minSdk 26) and
		// Windows 10 have no TLS 1.3; see internal/tlsutil for the full reasoning.
		log.Info("relay listening (TLS)", "addr", cfg.Listen, "min_version", "TLS 1.2")
		// The certificate is already in srv.TLSConfig, so the file arguments are empty.
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("listener: %w", err)
	case <-ctx.Done():
		log.Info("shutdown signal received, draining connections", "grace", shutdownGrace)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown did not complete", "err", err)
	}
	if metricsSrv != nil {
		_ = metricsSrv.Shutdown(shutdownCtx)
	}

	// Scrub anything buffered so that a graceful stop leaves no user data even in a
	// subsequently captured memory image.
	if q != nil {
		q.Clear()
		log.Info("buffered envelopes discarded")
	}

	log.Info("stopped")
	return nil
}

// buildTLS selects the transport configuration.
//
// Priority: an operator-supplied certificate pair, then the persistent self-signed
// certificate. There is deliberately no third branch that contacts an ACME server.
func buildTLS(cfg config.Config, stateDir string, log *slog.Logger) (*tls.Config, string, error) {
	if tlsutil.CertFileExists(cfg.TLS.CertFile, cfg.TLS.KeyFile) {
		cert, err := tlsutil.LoadCertificate(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, "", err
		}
		fp := tlsutil.Fingerprint(cert.Leaf)
		log.Info("using the configured certificate", "cert", cfg.TLS.CertFile, "fingerprint", tlsutil.DisplayFingerprint(fp))
		return tlsutil.ServerConfig(cert), fp, nil
	}

	if cfg.TLS.CertFile != "" || cfg.TLS.KeyFile != "" {
		return nil, "", fmt.Errorf("config: tls.cert_file and tls.key_file must both be set")
	}

	if cfg.TLS.Domain != "" {
		log.Warn("tls.domain is set, but this server does not obtain certificates automatically. " +
			"Terminate public TLS at a reverse proxy (Caddy does this with no configuration), " +
			"or supply --cert-file and --key-file. Falling back to a self-signed certificate.")
	}

	if stateDir == "" {
		cert, err := tlsutil.SelfSigned(tlsutil.HostsFor(cfg.PublicHost), tlsutil.DefaultValidity)
		if err != nil {
			return nil, "", err
		}
		fp := tlsutil.Fingerprint(cert.Leaf)
		log.Warn("no state directory configured: the self-signed certificate is ephemeral, " +
			"so its fingerprint will change on every restart and every configured client will need to be re-added")
		return tlsutil.ServerConfig(cert), fp, nil
	}

	cert, created, err := tlsutil.LoadOrCreateSelfSigned(stateDir, tlsutil.HostsFor(cfg.PublicHost), tlsutil.DefaultValidity)
	if err != nil {
		return nil, "", err
	}
	if created {
		log.Info("generated a new self-signed certificate", "state_dir", stateDir)
	} else {
		log.Info("reusing the persisted self-signed certificate", "state_dir", stateDir)
	}

	return tlsutil.ServerConfig(cert), tlsutil.Fingerprint(cert.Leaf), nil
}

// defaultStateDir returns a writable per-user location for the certificate.
//
// A cache directory is used rather than a system state directory because it needs
// no privileges, which matters for the "start it in two minutes with no
// configuration" path. Operators running as a service should point --state-dir at
// a proper location such as /var/lib/schat.
func defaultStateDir() string {
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return filepath.Join(dir, "schat")
	}
	return ".schat"
}

// newLogger builds the structured logger.
//
// No call site logs an envelope, and the log handler has no formatter that could:
// the payloads are never passed to the logger in the first place.
func newLogger(cfg config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}

	var h slog.Handler
	if cfg.Log.Format == "json" {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(h)
}

// printBanner tells the operator exactly what they got, with no guessing.
func printBanner(cfg config.Config, stateDir, fingerprint string, noTLS bool, log *slog.Logger) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	host, port := cfg.HostPort()

	fmt.Println()
	fmt.Println("  SCHAT relay server")
	fmt.Println("  " + version.String())
	fmt.Println()
	fmt.Printf("  %-14s %s\n", "Mode:", cfg.Mode)
	fmt.Printf("  %-14s %s\n", "Listen:", cfg.Listen)
	fmt.Printf("  %-14s %s:%s\n", "Public host:", host, port)
	if noTLS {
		fmt.Printf("  %-14s %s\n", "TLS:", "DISABLED (plaintext; local debugging only)")
	} else if cfg.TLS.CertFile != "" {
		fmt.Printf("  %-14s %s\n", "TLS:", "operator certificate")
	} else {
		fmt.Printf("  %-14s %s\n", "TLS:", "self-signed, pinned by clients")
	}
	if stateDir != "" && !noTLS && cfg.TLS.CertFile == "" {
		fmt.Printf("  %-14s %s\n", "State dir:", stateDir)
	}
	fmt.Printf("  %-14s %d MiB\n", "Heap:", ms.HeapAlloc>>20)
	fmt.Println()

	if fingerprint != "" {
		fmt.Println("  Certificate fingerprint (SHA-256):")
		fmt.Printf("    %s\n", tlsutil.DisplayFingerprint(fingerprint))
		fmt.Println()
	}

	fmt.Println("  Client connection URI:")
	fmt.Printf("    %s\n", cfg.ConnectURI(fingerprint))
	fmt.Println()

	log.Info("configuration accepted",
		"mode", cfg.Mode,
		"listen", cfg.Listen,
		"public_host", host,
		"storage", "none")

	if cfg.Mode == config.ModeLive {
		log.Info("retention policy: nothing is written to disk and nothing is queued")
	} else {
		log.Info("retention policy: envelopes are held in RAM only, never written to disk")
	}
}

// startupNotices lists what is deliberately still missing, so that nobody mistakes
// this build for a finished relay.
//
// It used to say "QR code rendering is not implemented yet (roadmap step 3c); use the
// printed URI". The client now renders QR codes, and this server never will: drawing one
// needs a third-party library, and "no third-party dependencies" is a property
// tools/verify.ps1 checks mechanically. Keeping the old wording would have told an
// operator that a feature was missing when it had moved to the client by design.
var startupNotices = []string{
	"the relay does not print a QR code, by design: it has no third-party dependencies. " +
		"The client shows a connection code that another device can scan",
	"group chat (MLS, roadmap step 6) and media transfer (step 7) are not implemented",
}

func healthHandler(cfg config.Config, c *metrics.Counters, gw *gateway.Gateway, keys *directory.Directory, fingerprint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		snap := c.Snapshot()
		identities, prekeys, _ := keys.Stats()
		writeJSON(w, map[string]any{
			"status":           "ok",
			"version":          version.Version,
			"protocol":         version.Protocol,
			"mode":             cfg.Mode,
			"storage":          "none",
			"uptime_seconds":   snap.UptimeSeconds,
			"live_connections": gw.ConnCount(),
			"fingerprint":      fingerprint,
			"prekey_directory": map[string]any{
				"identities":       identities,
				"one_time_prekeys": prekeys,
				"note":             "public key material only; held in RAM, never written to disk",
			},
			"unimplemented": startupNotices,
		})
	}
}

func publicConfigHandler(cfg config.Config, fingerprint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, port := cfg.HostPort()
		writeJSON(w, map[string]any{
			"name":        cfg.Name,
			"protocol":    version.Protocol,
			"host":        host,
			"port":        port,
			"mode":        cfg.Mode,
			"self_signed": cfg.TLS.CertFile == "",
			"fingerprint": fingerprint,
		})
	}
}

func metricsHandler(c *metrics.Counters, r *router.Router, q *queue.Queue, gw *gateway.Gateway) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if q != nil {
			_, envelopes, bytes, _ := q.Stats()
			c.SetQueueDepth(envelopes, bytes)
		}
		mailboxes, connections := r.Stats()
		c.SetMailboxes(mailboxes)

		writeJSON(w, map[string]any{
			"version":  version.Version,
			"counters": c.Snapshot(),
			"router": map[string]any{
				"mailboxes":           mailboxes,
				"router_connections":  connections,
				"gateway_connections": gw.ConnCount(),
			},
		})
	}
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

// sweepLoop reclaims expired buffered envelopes.
func sweepLoop(ctx context.Context, q *queue.Queue, log *slog.Logger) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if dropped := q.Sweep(); dropped > 0 {
				log.Debug("swept expired envelopes", "dropped", dropped)
			}
		}
	}
}
