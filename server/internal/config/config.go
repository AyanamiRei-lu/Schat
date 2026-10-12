// Package config loads and validates relay server settings.
//
// The guiding requirement (SCHAT.md section 10) is that standing up a server must
// not be hard. Every setting has a working default, so `schat-server` with no
// arguments and no configuration file starts successfully and prints a QR code.
// A configuration file is strictly optional.
//
// JSON is used rather than YAML on purpose: encoding/json is in the standard
// library, and the extra dependency is not worth it for a dozen keys. See the
// note in server/go.mod.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Mode selects the delivery behaviour of the relay.
type Mode string

const (
	// ModeLive forwards only when the recipient is connected. Nothing is ever
	// held, so the server's memory contains user data for microseconds.
	ModeLive Mode = "live"

	// ModeBuffer holds envelopes in RAM for a bounded time so that a briefly
	// offline recipient can still receive them. The process never writes to
	// disk, so a restart loses the queue by design.
	ModeBuffer Mode = "buffer"
)

// Default values. These are chosen so that a zero-configuration start is both
// useful and safe.
const (
	DefaultListen          = "0.0.0.0:8443"
	DefaultMetricsListen   = "127.0.0.1:9090"
	DefaultMode            = ModeLive
	DefaultBufferTTL       = 72 * time.Hour
	DefaultMaxPerToken     = 100
	DefaultMaxGlobalMemory = 512 << 20 // 512 MiB
	DefaultMaxEnvelopeSize = 8 << 20   // 8 MiB
	DefaultSendRatePerSec  = 200
	DefaultIdleTimeout     = 5 * time.Minute
	DefaultServerName      = "schat"
)

// Buffer configures in-memory store-and-forward. It has no effect in live mode.
type Buffer struct {
	// TTL is how long an envelope may wait for an offline recipient.
	TTL time.Duration `json:"ttl"`

	// MaxPerToken bounds a single mailbox.
	MaxPerToken int `json:"max_per_token"`

	// MaxGlobalMemory bounds the whole queue so that the process cannot be
	// pushed into an out-of-memory kill by traffic alone.
	MaxGlobalMemory int64 `json:"max_global_memory"`
}

// Limits configures the abuse-resistance ceilings.
type Limits struct {
	// MaxEnvelopeSize rejects oversized envelopes. Larger media is expected to
	// travel over a direct peer-to-peer path instead.
	MaxEnvelopeSize int64 `json:"max_envelope_size"`

	// SendRatePerSec throttles a single connection.
	SendRatePerSec int `json:"send_rate_per_sec"`

	// IdleTimeout closes connections that stop sending heartbeats.
	IdleTimeout time.Duration `json:"idle_timeout"`
}

// TLS configures transport security.
type TLS struct {
	// Domain names the public host this server is reached at. It is kept as a
	// separate field for backwards compatibility with configurations and command
	// lines written before --public-host existed, and it does NOT cause the server
	// to obtain a certificate: that would require an ACME client and therefore the
	// server's first third-party dependency. See internal/tlsutil for the full
	// reasoning, and prefer PublicHost for new configurations.
	Domain string `json:"domain"`

	// Email is the ACME account contact, optional.
	Email string `json:"email"`

	// CertFile and KeyFile allow using an operator-provided certificate instead.
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`

	// SelfSigned generates an ephemeral self-signed certificate when no domain
	// and no certificate files are configured. Clients pin the fingerprint
	// printed alongside the QR code.
	SelfSigned bool `json:"self_signed"`
}

// Log configures logging. There is no setting that enables logging message
// content, and there never will be: the server holds no key that could decrypt
// it, and the log formatter refuses to print envelopes.
type Log struct {
	// Level is one of debug, info, warn, error.
	Level string `json:"level"`

	// Format is "text" or "json".
	Format string `json:"format"`
}

// Config is the complete server configuration.
type Config struct {
	// Listen is the public listener address, host:port.
	Listen string `json:"listen"`

	// PublicHost is the host name or IP address that clients should dial. It is
	// what appears in the connection URI, and it is the only field that decides
	// what a client connects to.
	//
	// This is deliberately SEPARATE from TLS.Domain. On a LAN the advertised host
	// is an IP such as 192.168.1.158, and an IP address can never obtain a Let's
	// Encrypt certificate. Conflating the two would silently disable the
	// self-signed certificate and leave the operator with a server that cannot
	// complete a TLS handshake:
	//
	//	TLS.Domain  = "obtain a publicly trusted certificate for this name"
	//	PublicHost  = "tell clients to dial this address"
	//
	// Use it for LAN testing:
	//
	//	schat-server --listen 0.0.0.0:8443 --public-host 192.168.1.158
	PublicHost string `json:"public_host"`

	// Name is a friendly label shown in the client after scanning the QR code.
	Name string `json:"name"`

	// Mode is live or buffer.
	Mode Mode `json:"mode"`

	Buffer Buffer `json:"buffer"`
	Limits Limits `json:"limits"`
	TLS    TLS    `json:"tls"`
	Log    Log    `json:"log"`

	// MetricsListen is the address of the health and metrics endpoint.
	MetricsListen string `json:"metrics_listen"`
}

// Default returns a configuration that is valid and safe with no user input.
//
// Self-signed TLS is the default because it is the only option that works
// without a domain name, and because SCHAT clients pin the certificate
// fingerprint delivered through the QR code, which makes a self-signed
// certificate both usable and safe against passive interception.
func Default() Config {
	return Config{
		Listen: DefaultListen,
		Name:   DefaultServerName,
		Mode:   DefaultMode,
		Buffer: Buffer{
			TTL:             DefaultBufferTTL,
			MaxPerToken:     DefaultMaxPerToken,
			MaxGlobalMemory: DefaultMaxGlobalMemory,
		},
		Limits: Limits{
			MaxEnvelopeSize: DefaultMaxEnvelopeSize,
			SendRatePerSec:  DefaultSendRatePerSec,
			IdleTimeout:     DefaultIdleTimeout,
		},
		TLS: TLS{
			SelfSigned: true,
		},
		Log: Log{
			Level:  "info",
			Format: "text",
		},
		MetricsListen: DefaultMetricsListen,
	}
}

// Load reads a JSON configuration file and layers it over the defaults.
//
// Fields absent from the file keep their default value, so a minimal file such
// as {"tls":{"domain":"chat.example.com"}} is a complete and valid
// configuration.
func Load(path string) (Config, error) {
	cfg := Default()

	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("config: reading %s: %w", path, err)
	}

	// An empty file is treated as "use all defaults" rather than an error.
	if len(strings.TrimSpace(string(raw))) == 0 {
		return cfg, nil
	}

	dec := json.NewDecoder(strings.NewReader(string(raw)))
	// Reject unknown keys: a typo such as "domian" must fail loudly instead of
	// silently leaving the server without a certificate.
	dec.DisallowUnknownFields()

	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("config: parsing %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Validate checks the configuration for internal consistency.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Listen) == "" {
		return errors.New("config: listen address must not be empty")
	}

	switch c.Mode {
	case ModeLive, ModeBuffer:
	default:
		return fmt.Errorf("config: unknown mode %q (want %q or %q)",
			c.Mode, ModeLive, ModeBuffer)
	}

	if c.Mode == ModeBuffer {
		if c.Buffer.TTL <= 0 {
			return errors.New("config: buffer.ttl must be positive in buffer mode")
		}
		if c.Buffer.MaxPerToken <= 0 {
			return errors.New("config: buffer.max_per_token must be positive in buffer mode")
		}
		if c.Buffer.MaxGlobalMemory <= 0 {
			return errors.New("config: buffer.max_global_memory must be positive in buffer mode")
		}
	}

	if c.Limits.MaxEnvelopeSize <= 0 {
		return errors.New("config: limits.max_envelope_size must be positive")
	}
	if c.Limits.SendRatePerSec <= 0 {
		return errors.New("config: limits.send_rate_per_sec must be positive")
	}
	if c.Limits.IdleTimeout < 0 {
		return errors.New("config: limits.idle_timeout must not be negative")
	}

	if c.TLS.CertFile != "" && c.TLS.KeyFile == "" {
		return errors.New("config: tls.cert_file set without tls.key_file")
	}
	if c.TLS.KeyFile != "" && c.TLS.CertFile == "" {
		return errors.New("config: tls.key_file set without tls.cert_file")
	}
	if c.TLS.Domain != "" && c.TLS.CertFile != "" {
		return errors.New("config: tls.domain and tls.cert_file are mutually exclusive")
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: unknown log level %q", c.Log.Level)
	}

	switch c.Log.Format {
	case "text", "json":
	default:
		return fmt.Errorf("config: unknown log format %q", c.Log.Format)
	}

	return nil
}

// UsesAutocert reports whether the server should obtain a certificate from Let's
// Encrypt for TLS.Domain.
func (c *Config) UsesAutocert() bool { return c.TLS.Domain != "" }

// HostPort splits the listen address, applying a default port when the
// configuration omits one.
//
// The advertised host is chosen in this order:
//
//  1. PublicHost, when set. This is how a LAN deployment names itself, e.g.
//     --public-host 192.168.1.158.
//  2. The concrete address from Listen, when it is not a wildcard.
//  3. TLS.Domain, a sensible guess for an internet-facing deployment.
//  4. "localhost", so that a zero-configuration local run still yields a usable
//     URI.
//
// Note that PublicHost takes precedence over TLS.Domain rather than the other way
// round: PublicHost is the explicit statement of intent, and an operator behind a
// reverse proxy legitimately advertises a different name from the certificate
// holder.
func (c *Config) HostPort() (host string, port string) {
	addr := c.Listen
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host, port = addr[:i], addr[i+1:]
	} else {
		host, port = addr, "8443"
	}

	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		switch {
		case c.PublicHost != "":
			host = c.PublicHost
		case c.TLS.Domain != "":
			host = c.TLS.Domain
		default:
			host = "localhost"
		}
	}
	if port == "" {
		port = "8443"
	}
	return host, port
}

// ConnectURI renders the schat:// URI that a client scans or pastes to adopt
// this server (SCHAT.md section 9.2).
//
// The certificate fingerprint is included because the default deployment uses a
// self-signed certificate; pinning the fingerprint is what makes that safe. The
// fingerprint is a public value and reveals nothing.
func (c *Config) ConnectURI(fingerprint string) string {
	host, port := c.HostPort()

	q := url.Values{}
	q.Set("h", host)
	q.Set("p", port)
	q.Set("n", c.Name)
	if fingerprint != "" {
		q.Set("fp", fingerprint)
	}
	if c.TLS.Domain == "" && c.TLS.CertFile == "" {
		q.Set("ss", "1") // self-signed: clients must expect a pinned certificate
	}

	return "schat://connect?" + q.Encode()
}
