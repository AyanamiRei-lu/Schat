package tlsutil

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSelfSignedProducesUsableCertificate(t *testing.T) {
	cert, err := SelfSigned([]string{"chat.example.com", "192.168.1.158"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("Leaf was not populated; a caller cannot compute a fingerprint without it")
	}

	leaf := cert.Leaf
	if !containsString(leaf.DNSNames, "chat.example.com") {
		t.Errorf("DNS SANs are %v, missing the configured host", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "192.168.1.158" {
		t.Errorf("IP SANs are %v, missing the configured address", leaf.IPAddresses)
	}
	if leaf.NotAfter.Before(time.Now()) {
		t.Error("the certificate is already expired")
	}
	// A small backward allowance keeps a client whose clock is slightly behind
	// from rejecting a freshly issued certificate.
	if leaf.NotBefore.After(time.Now()) {
		t.Error("NotBefore is in the future, which would break clients with correct clocks")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("the certificate cannot sign, so it cannot complete a handshake")
	}
	if len(leaf.ExtKeyUsage) == 0 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage is %v, want server auth", leaf.ExtKeyUsage)
	}
}

// TestSelfSignedWithoutHostsStillWorks guards the degenerate case: a certificate
// with no subject alternative names is rejected by every modern client, so the
// generator must fall back rather than emit something unusable.
func TestSelfSignedWithoutHostsStillWorks(t *testing.T) {
	cert, err := SelfSigned(nil, 0) // zero validity must also fall back
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}
	if len(cert.Leaf.DNSNames) == 0 && len(cert.Leaf.IPAddresses) == 0 {
		t.Fatal("a certificate with no names at all was issued")
	}
	if !containsString(cert.Leaf.DNSNames, "localhost") {
		t.Errorf("expected a localhost fallback, got %v", cert.Leaf.DNSNames)
	}
}

func TestSelfSignedIsUniquePerCall(t *testing.T) {
	a, err := SelfSigned([]string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}
	b, err := SelfSigned([]string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}

	// A regenerated certificate every start is the point; two runs must not share
	// a key or a serial number.
	if Fingerprint(a.Leaf) == Fingerprint(b.Leaf) {
		t.Fatal("two invocations produced the same certificate")
	}
	if a.Leaf.SerialNumber.Cmp(b.Leaf.SerialNumber) == 0 {
		t.Fatal("two invocations produced the same serial number")
	}
}

func TestFingerprintIsSHA256Hex(t *testing.T) {
	cert, err := SelfSigned([]string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}

	fp := Fingerprint(cert.Leaf)
	if len(fp) != 64 {
		t.Fatalf("fingerprint is %d characters, want 64", len(fp))
	}
	if _, err := hex.DecodeString(fp); err != nil {
		t.Fatalf("fingerprint is not hex: %v", err)
	}
	if strings.ToLower(fp) != fp {
		t.Error("fingerprint should be lower case so it survives a URI unescaped")
	}

	// Recompute independently rather than trusting the function under test.
	sum := sha256.Sum256(cert.Leaf.Raw)
	if fp != hex.EncodeToString(sum[:]) {
		t.Fatal("fingerprint does not match an independent SHA-256 of the DER")
	}

	// A nil certificate must not panic, because the caller may be rendering a URI
	// before TLS is set up.
	if Fingerprint(nil) != "" {
		t.Error("Fingerprint(nil) should return an empty string")
	}
}

func TestDisplayFingerprint(t *testing.T) {
	const raw = "aabbccdd"
	if got, want := DisplayFingerprint(raw), "AA:BB:CC:DD"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// Accept the colon-separated form as input too, so a user can paste back what
	// the client displayed.
	if got, want := DisplayFingerprint("AA:BB:CC:DD"), "AA:BB:CC:DD"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// An odd-length input must not panic on the slicing.
	_ = DisplayFingerprint("abc")
}

// TestServerConfigIsHardened pins the transport choices that matter.
func TestServerConfigIsHardened(t *testing.T) {
	cert, err := SelfSigned([]string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}

	cfg := ServerConfig(cert)

	// The floor is TLS 1.2 on purpose: Android 8/9 (minSdk 26) and Windows 10 have
	// no TLS 1.3, so requiring it would lock out part of the supported client base.
	// Security comes from Go's default 1.2 cipher suites, which are all ECDHE+AEAD.
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion is %#x, want TLS 1.2 so that Android 8/9 can connect", cfg.MinVersion)
	}
	if cfg.MinVersion > tls.VersionTLS12 {
		t.Error("a floor above TLS 1.2 would exclude devices this project supports")
	}

	// HTTP/2 cannot be hijacked, so advertising it would let a client negotiate a
	// protocol on which the WebSocket upgrade can never succeed.
	for _, proto := range cfg.NextProtos {
		if proto != "http/1.1" {
			t.Errorf("NextProtos advertises %q; only http/1.1 can carry a WebSocket upgrade", proto)
		}
	}
	if len(cfg.NextProtos) != 1 {
		t.Errorf("NextProtos is %v, want exactly http/1.1", cfg.NextProtos)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected exactly one certificate, got %d", len(cfg.Certificates))
	}
}

// TestRealTLSHandshake proves the generated certificate is not merely
// well-formed: a client that trusts it must be able to complete a handshake.
//
// It uses a real loopback TCP listener rather than net.Pipe. net.Pipe is
// unbuffered and synchronous, so two peers that each write a handshake flight
// before reading deadlock against each other — which is precisely what this test
// did on its first run. A kernel-socket pair has buffers and therefore does not
// manufacture a bug that the real transport does not have.
func TestRealTLSHandshake(t *testing.T) {
	cert, err := SelfSigned([]string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer raw.Close()

		tlsServer := tls.Server(raw, ServerConfig(cert))
		defer tlsServer.Close()

		if err := tlsServer.Handshake(); err != nil {
			serverErr <- err
			return
		}
		_, err = tlsServer.Write([]byte("relay says hello"))
		serverErr <- err
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	defer raw.Close()

	tlsClient := tls.Client(raw, &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	defer tlsClient.Close()

	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}

	// The server must not accept anything below its declared floor, and the
	// negotiated version must be at least that. Asserting the floor rather than an
	// exact version keeps the test meaningful whichever version the peers pick.
	v := tlsClient.ConnectionState().Version
	if v < tls.VersionTLS12 {
		t.Errorf("negotiated %#x, below the TLS 1.2 floor", v)
	}
	if v < ServerConfig(cert).MinVersion {
		t.Errorf("negotiated %#x, below the configured minimum %#x", v, ServerConfig(cert).MinVersion)
	}

	// Confirm the certificate the client saw is the one whose fingerprint the
	// connection URI carries. This is the pinning contract in one assertion.
	peer := tlsClient.ConnectionState().PeerCertificates
	if len(peer) == 0 {
		t.Fatal("no peer certificate")
	}
	if Fingerprint(peer[0]) != Fingerprint(cert.Leaf) {
		t.Fatal("the fingerprint the client observed differs from the one advertised")
	}

	const want = "relay says hello"
	buf := make([]byte, len(want))
	if _, err := readFull(tlsClient, buf); err != nil {
		t.Fatalf("reading from the server: %v", err)
	}
	if string(buf) != want {
		t.Fatalf("got %q, want %q", buf, want)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server side: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server goroutine did not finish")
	}
}

func TestLoadCertificateMissingFiles(t *testing.T) {
	if _, err := LoadCertificate(
		filepath.Join(t.TempDir(), "nope.pem"),
		filepath.Join(t.TempDir(), "nope.key"),
	); err == nil {
		t.Fatal("expected an error for missing certificate files")
	}
}

func TestCertFileExists(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if CertFileExists(certPath, keyPath) {
		t.Fatal("reported a certificate pair that does not exist")
	}
	if CertFileExists("", "") {
		t.Fatal("reported an empty configuration as existing")
	}
	if CertFileExists(certPath, "") {
		t.Fatal("reported a half-configured pair as existing")
	}
}

func TestHostsForIncludesLoopbackAndPublicHost(t *testing.T) {
	hosts := HostsFor("192.168.1.158")

	for _, want := range []string{"localhost", "127.0.0.1", "::1", "192.168.1.158"} {
		if !containsString(hosts, want) {
			t.Errorf("hosts %v is missing %q", hosts, want)
		}
	}

	// Duplicates must be removed: a certificate with a repeated SAN is legal but
	// looks like a bug in every diagnostic.
	seen := map[string]int{}
	for _, h := range hosts {
		seen[h]++
	}
	for h, n := range seen {
		if n > 1 {
			t.Errorf("host %q appears %d times", h, n)
		}
	}
}

func TestHostsForEmptyPublicHost(t *testing.T) {
	hosts := HostsFor("   ")
	if !containsString(hosts, "localhost") {
		t.Fatalf("hosts %v is missing localhost", hosts)
	}
}

// TestPersistedCertificateKeepsItsFingerprint is the property that makes "scan
// once" survive a restart. Without persistence every bounce of the service would
// invalidate every configured client.
func TestPersistedCertificateKeepsItsFingerprint(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"localhost", "127.0.0.1"}

	first, created, err := LoadOrCreateSelfSigned(dir, hosts, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if !created {
		t.Fatal("the first call should have generated a certificate")
	}

	second, created, err := LoadOrCreateSelfSigned(dir, hosts, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if created {
		t.Fatal("the second call regenerated a certificate that was still valid")
	}
	if Fingerprint(first.Leaf) != Fingerprint(second.Leaf) {
		t.Fatal("the fingerprint changed across a restart, which would break every configured client")
	}

	// The key material must have been reloaded, not merely the certificate.
	if second.PrivateKey == nil {
		t.Fatal("the persisted key was not loaded")
	}
}

func TestPersistedCertificateRotatesWhenHostsChange(t *testing.T) {
	dir := t.TempDir()

	if _, _, err := LoadOrCreateSelfSigned(dir, []string{"localhost"}, 30*24*time.Hour); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// A new public host, as happens when a DHCP lease moves.
	_, created, err := LoadOrCreateSelfSigned(dir, []string{"localhost", "192.168.1.42"}, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !created {
		t.Fatal("a certificate that no longer covers the configured host must be replaced")
	}
}

func TestPersistedCertificateRotatesNearExpiry(t *testing.T) {
	dir := t.TempDir()

	// A validity half the rotation threshold means it is already due.
	if _, _, err := LoadOrCreateSelfSigned(dir, []string{"localhost"}, rotateBefore/2); err != nil {
		t.Fatalf("first call: %v", err)
	}

	_, created, err := LoadOrCreateSelfSigned(dir, []string{"localhost"}, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !created {
		t.Fatal("a certificate inside the rotation window must be replaced")
	}
}

func TestLoadOrCreateSelfSignedRejectsEmptyDir(t *testing.T) {
	if _, _, err := LoadOrCreateSelfSigned("  ", []string{"localhost"}, time.Hour); err == nil {
		t.Fatal("expected an error for an empty state directory")
	}
}

func TestPersistedKeyIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := LoadOrCreateSelfSigned(dir, []string{"localhost"}, 30*24*time.Hour); err != nil {
		t.Fatalf("LoadOrCreateSelfSigned: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, SelfSignedKeyName))
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	// Windows does not implement POSIX permission bits, so only assert where they
	// are meaningful.
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Fatalf("private key permissions are %#o, want no group or world access", perm)
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
