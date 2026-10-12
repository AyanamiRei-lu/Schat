package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultIsValid(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the default configuration must be valid, got: %v", err)
	}
	if cfg.Mode != ModeLive {
		t.Fatalf("the default mode must be live (zero retention), got %q", cfg.Mode)
	}
	if !cfg.TLS.SelfSigned {
		t.Fatal("the default configuration must enable self-signed TLS so that it works without a domain")
	}
}

// TestZeroConfigStarts is the requirement-8 guarantee in test form: no file, no
// flags, no environment, still valid.
func TestZeroConfigStarts(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("zero configuration must be usable: %v", err)
	}

	host, port := cfg.HostPort()
	if host == "" || port == "" {
		t.Fatalf("zero configuration produced an unusable address %q:%q", host, port)
	}
	if uri := cfg.ConnectURI(""); !strings.HasPrefix(uri, "schat://connect?") {
		t.Fatalf("connect URI has the wrong scheme: %q", uri)
	}
}

func TestLoadMinimalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "schat.json")

	// A one-key file must be a complete configuration.
	body := `{"tls": {"domain": "chat.example.com"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TLS.Domain != "chat.example.com" {
		t.Fatalf("domain was not applied: %q", cfg.TLS.Domain)
	}
	// Values absent from the file must keep their defaults.
	if cfg.Mode != DefaultMode {
		t.Fatalf("mode should have kept its default, got %q", cfg.Mode)
	}
	if cfg.Limits.MaxEnvelopeSize != DefaultMaxEnvelopeSize {
		t.Fatal("limits should have kept their defaults")
	}
	if !cfg.UsesAutocert() {
		t.Fatal("a configured domain must enable autocert")
	}
}

func TestLoadEmptyFileUsesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != DefaultListen {
		t.Fatalf("got listen %q, want the default %q", cfg.Listen, DefaultListen)
	}
}

// TestLoadRejectsTypo is a usability guard: a misspelled key must fail loudly
// rather than silently leaving the server misconfigured.
func TestLoadRejectsTypo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "typo.json")
	if err := os.WriteFile(path, []byte(`{"domian": "chat.example.com"}`), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown configuration key")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected an error for a missing configuration file")
	}
}

func TestValidateRejectsBadMode(t *testing.T) {
	cfg := Default()
	cfg.Mode = Mode("cloud")
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for an unknown mode")
	}
}

func TestValidateRejectsEmptyListen(t *testing.T) {
	cfg := Default()
	cfg.Listen = "  "
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for an empty listen address")
	}
}

func TestValidateBufferModeRequiresBounds(t *testing.T) {
	cfg := Default()
	cfg.Mode = ModeBuffer

	cfg.Buffer.TTL = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for a zero TTL in buffer mode")
	}

	cfg = Default()
	cfg.Mode = ModeBuffer
	cfg.Buffer.MaxGlobalMemory = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for an unbounded queue in buffer mode")
	}
}

func TestValidateBufferModeAcceptsDefaults(t *testing.T) {
	cfg := Default()
	cfg.Mode = ModeBuffer
	if err := cfg.Validate(); err != nil {
		t.Fatalf("buffer mode with default bounds must be valid: %v", err)
	}
}

func TestValidateTLSConsistency(t *testing.T) {
	cfg := Default()
	cfg.TLS.CertFile = "/etc/schat/cert.pem"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for cert_file without key_file")
	}

	cfg = Default()
	cfg.TLS.KeyFile = "/etc/schat/key.pem"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for key_file without cert_file")
	}

	cfg = Default()
	cfg.TLS.CertFile = "/etc/schat/cert.pem"
	cfg.TLS.KeyFile = "/etc/schat/key.pem"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a certificate pair must be valid: %v", err)
	}

	// A domain and an explicit certificate are two answers to the same
	// question; accepting both would make the effective behaviour ambiguous.
	cfg = Default()
	cfg.TLS.Domain = "chat.example.com"
	cfg.TLS.CertFile = "/etc/schat/cert.pem"
	cfg.TLS.KeyFile = "/etc/schat/key.pem"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error when both a domain and certificate files are set")
	}
}

func TestValidateLogSettings(t *testing.T) {
	cfg := Default()
	cfg.Log.Level = "verbose"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for an unknown log level")
	}

	cfg = Default()
	cfg.Log.Format = "xml"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for an unknown log format")
	}
}

// TestConnectURIContents pins the URI contract that clients parse.
func TestConnectURIContents(t *testing.T) {
	cfg := Default()
	cfg.Listen = "0.0.0.0:8443"
	cfg.Name = "family"

	uri := cfg.ConnectURI("AABBCC")

	for _, want := range []string{
		"schat://connect?",
		"h=localhost",
		"p=8443",
		"n=family",
		"fp=AABBCC",
		"ss=1", // self-signed marker
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("connect URI %q is missing %q", uri, want)
		}
	}
}

func TestConnectURIUsesDomainOverWildcardBind(t *testing.T) {
	cfg := Default()
	cfg.Listen = "0.0.0.0:443"
	cfg.TLS.Domain = "chat.example.com"
	cfg.TLS.SelfSigned = false

	uri := cfg.ConnectURI("")

	if !strings.Contains(uri, "h=chat.example.com") {
		t.Errorf("expected the domain in the URI, got %q", uri)
	}
	// With a real certificate there is nothing for the client to pin, and the
	// self-signed marker must not be present.
	if strings.Contains(uri, "ss=1") {
		t.Errorf("self-signed marker present for a CA-issued certificate: %q", uri)
	}
}

func TestHostPortDefaults(t *testing.T) {
	cfg := Default()
	cfg.Listen = "127.0.0.1"
	host, port := cfg.HostPort()
	if host != "127.0.0.1" || port != "8443" {
		t.Fatalf("got %q:%q, want 127.0.0.1:8443", host, port)
	}
}

// TestHostPortPrefersPublicHost covers the LAN case: the advertised host is an IP
// address and must win over the wildcard listen address, because it is the only
// field that says where a client should dial.
func TestHostPortPrefersPublicHost(t *testing.T) {
	cfg := Default()
	cfg.Listen = "0.0.0.0:8443"
	cfg.PublicHost = "192.168.1.158"

	host, port := cfg.HostPort()
	if host != "192.168.1.158" || port != "8443" {
		t.Fatalf("got %q:%q, want 192.168.1.158:8443", host, port)
	}
}

// TestPublicHostDoesNotEnableAutocert is the regression test for the bug that
// --public-host was introduced to fix.
//
// Before it existed, the only way to advertise anything other than "localhost"
// was --domain, which also means "obtain a Let's Encrypt certificate". Using that
// with a LAN address silently disabled the self-signed certificate and pointed
// the server at an ACME flow that can never succeed for a private IP.
func TestPublicHostDoesNotEnableAutocert(t *testing.T) {
	cfg := Default()
	cfg.Listen = "0.0.0.0:8443"
	cfg.PublicHost = "192.168.1.158"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("a LAN configuration must be valid: %v", err)
	}
	if cfg.UsesAutocert() {
		t.Fatal("advertising a LAN address must not enable Let's Encrypt")
	}

	uri := cfg.ConnectURI("")
	if !strings.Contains(uri, "h=192.168.1.158") {
		t.Errorf("URI is missing the LAN address: %q", uri)
	}
	if !strings.Contains(uri, "ss=1") {
		t.Errorf("URI must mark a pinned self-signed certificate: %q", uri)
	}
}

func TestHostPortFallsBackToTLSDomain(t *testing.T) {
	cfg := Default()
	cfg.Listen = "0.0.0.0:443"
	cfg.TLS.Domain = "chat.example.com"

	host, port := cfg.HostPort()
	if host != "chat.example.com" || port != "443" {
		t.Fatalf("got %q:%q, want chat.example.com:443", host, port)
	}
}

func TestHostPortPrefersPublicHostOverTLSDomain(t *testing.T) {
	// An operator behind a reverse proxy advertises a name that differs from the
	// certificate holder; the explicit setting must win.
	cfg := Default()
	cfg.Listen = "0.0.0.0:8443"
	cfg.PublicHost = "chat.example.com"
	cfg.TLS.Domain = "internal.example.net"

	host, _ := cfg.HostPort()
	if host != "chat.example.com" {
		t.Fatalf("got %q, want chat.example.com", host)
	}
}

func TestHostPortHandlesIPv6Wildcard(t *testing.T) {
	cfg := Default()
	cfg.Listen = "[::]:8443"
	cfg.PublicHost = "192.168.1.158"

	host, port := cfg.HostPort()
	if host != "192.168.1.158" || port != "8443" {
		t.Fatalf("got %q:%q, want 192.168.1.158:8443", host, port)
	}
}

func TestConnectURICarriesFingerprint(t *testing.T) {
	cfg := Default()
	cfg.Listen = "0.0.0.0:8443"
	cfg.PublicHost = "192.168.1.158"

	uri := cfg.ConnectURI("DEADBEEF")
	if !strings.Contains(uri, "fp=DEADBEEF") {
		t.Errorf("URI is missing the pinned fingerprint: %q", uri)
	}
}

// TestLoadLANConfig is the end-to-end check for the documented LAN recipe.
func TestLoadLANConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lan.json")

	body := `{
	  "listen": "0.0.0.0:8443",
	  "public_host": "192.168.1.158",
	  "mode": "buffer",
	  "name": "lan-test"
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PublicHost != "192.168.1.158" {
		t.Fatalf("public_host was not applied: %q", cfg.PublicHost)
	}
	if cfg.Mode != ModeBuffer {
		t.Fatalf("mode was not applied: %q", cfg.Mode)
	}
	if cfg.UsesAutocert() {
		t.Fatal("a LAN configuration must not enable Let's Encrypt")
	}

	uri := cfg.ConnectURI("")
	for _, want := range []string{"h=192.168.1.158", "p=8443", "n=lan-test", "ss=1"} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI %q is missing %q", uri, want)
		}
	}
}

func TestBufferDefaultsAreBounded(t *testing.T) {
	cfg := Default()
	if cfg.Buffer.MaxGlobalMemory <= 0 {
		t.Fatal("the global queue must always be bounded")
	}
	if cfg.Buffer.MaxPerToken <= 0 {
		t.Fatal("per-token queues must always be bounded")
	}
	if cfg.Buffer.TTL > 7*24*time.Hour {
		t.Fatalf("the buffer TTL (%s) is longer than a week, which stretches the meaning of 'temporary'", cfg.Buffer.TTL)
	}
}
