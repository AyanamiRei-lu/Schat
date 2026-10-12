// Package tlsutil produces the transport security configuration for the relay.
//
// # Why the server terminates TLS at all
//
// SCHAT encrypts message content end to end, so the relay cannot read it whether
// or not the transport is protected. TLS still matters, for two reasons that are
// easy to state precisely:
//
//   - Metadata. Envelope sizes, timings and the delivery token being used are all
//     visible to a passive network observer without TLS. SCHAT.md section 4.7
//     describes what the token scheme hides from the *server*; TLS is what stops
//     the same information leaking to everyone on the path.
//   - Integrity of the routing header. A network attacker who can rewrite the
//     delivery token redirects traffic without touching any ciphertext.
//
// # What this package deliberately does NOT do
//
// There is no ACME client here, and therefore no automatic Let's Encrypt
// certificate. Pulling in golang.org/x/crypto/acme/autocert would make the server
// module's first third-party dependency, which would break the property that
// `go list -m all` in server/ lists nothing but the module itself — the mechanical
// basis for the supply-chain claim in SCHAT.md section 7.2.
//
// Public deployments terminate TLS at a reverse proxy (Caddy obtains and renews
// certificates with no configuration at all, which is *easier* than doing it here)
// and forward to the relay over loopback. Deployments with their own certificate
// use --cert-file and --key-file. Everything else gets the self-signed certificate
// below, whose fingerprint the client pins after scanning the connection URI.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultValidity is how long an ephemeral self-signed certificate is valid.
//
// It is deliberately short. The certificate is regenerated on every start and the
// client pins the fingerprint, so there is no renewal story to get wrong and no
// long-lived key sitting on disk. A short life also limits the value of a leaked
// certificate, which in any case grants only impersonation of a server whose
// content the attacker still cannot read.
const DefaultValidity = 30 * 24 * time.Hour

// SelfSigned generates an ephemeral self-signed certificate for the given hosts.
//
// hosts may contain DNS names and IP literals; both end up as subject alternative
// names, which is what a client actually validates. The key is ECDSA P-256: small,
// fast, and free of the parameter-generation pitfalls of RSA.
func SelfSigned(hosts []string, validity time.Duration) (tls.Certificate, error) {
	if validity <= 0 {
		validity = DefaultValidity
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsutil: generating key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsutil: generating serial: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour) // tolerate modest clock skew
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   firstNonEmpty(hosts, "schat"),
			Organization: []string{"SCHAT self-signed"},
		},
		NotBefore: notBefore,
		// NotAfter is measured from NOW, not from NotBefore. Deriving it from
		// NotBefore silently shortens every certificate by the clock-skew
		// allowance: a one-hour certificate computed that way expires the instant
		// it is issued. The unit test for this caught exactly that.
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, h)
	}

	// A certificate with no names at all cannot be validated by anyone, so fall
	// back to localhost rather than issuing something useless.
	if len(template.DNSNames) == 0 && len(template.IPAddresses) == 0 {
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsutil: creating certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsutil: marshalling key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsutil: assembling key pair: %w", err)
	}
	cert.Leaf, err = x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsutil: parsing generated certificate: %w", err)
	}
	return cert, nil
}

// LoadCertificate reads a PEM certificate and key from disk.
func LoadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsutil: loading %s and %s: %w", certFile, keyFile, err)
	}
	// Populate Leaf so that the fingerprint can be computed without reparsing.
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("tlsutil: parsing leaf certificate: %w", err)
		}
		cert.Leaf = leaf
	}
	return cert, nil
}

// Names of the persisted self-signed key pair within the state directory.
const (
	SelfSignedCertName = "self-signed-cert.pem"
	SelfSignedKeyName  = "self-signed-key.pem"
)

// rotateBefore is how much remaining validity triggers regeneration.
const rotateBefore = 7 * 24 * time.Hour

// LoadOrCreateSelfSigned returns the persisted self-signed certificate for this
// server, generating one if there is none worth keeping.
//
// # Why persistence matters
//
// Clients pin the certificate fingerprint they received in the connection URI.
// A certificate regenerated on every start would therefore break every configured
// client on every restart, and the operator would have to re-scan a QR code each
// time the service bounced. Persisting the key pair turns "configure once" into
// something that actually stays configured.
//
// The certificate is regenerated when it is missing, unreadable, within
// rotateBefore of expiry, or no longer covers one of the configured hosts (an
// address change usually means a DHCP lease moved). Regeneration is safe: it costs
// a re-scan, not a compromise.
func LoadOrCreateSelfSigned(dir string, hosts []string, validity time.Duration) (tls.Certificate, bool, error) {
	if strings.TrimSpace(dir) == "" {
		return tls.Certificate{}, false, errors.New("tlsutil: empty state directory")
	}

	certPath := filepath.Join(dir, SelfSignedCertName)
	keyPath := filepath.Join(dir, SelfSignedKeyName)

	if CertFileExists(certPath, keyPath) {
		if cert, err := LoadCertificate(certPath, keyPath); err == nil && cert.Leaf != nil {
			if time.Until(cert.Leaf.NotAfter) > rotateBefore && certCovers(cert.Leaf, hosts) {
				return cert, false, nil
			}
		}
		// Fall through: a certificate that is unreadable, expiring, or missing a
		// configured name is worse than a fresh fingerprint.
	}

	cert, err := SelfSigned(hosts, validity)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	if err := persistCertificate(dir, cert); err != nil {
		return tls.Certificate{}, false, err
	}
	return cert, true, nil
}

// persistCertificate writes the certificate and key into the state directory.
//
// The private key is written with 0600 and the directory with 0700. This is not a
// long-term secret — it protects only the transport to a server that cannot read
// message content — but there is no reason to leave it world-readable either.
func persistCertificate(dir string, cert tls.Certificate) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("tlsutil: creating state directory %s: %w", dir, err)
	}

	priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("tlsutil: unexpected private key type %T", cert.PrivateKey)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("tlsutil: marshalling private key: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return errors.New("tlsutil: certificate has no DER content")
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})

	if err := os.WriteFile(filepath.Join(dir, SelfSignedKeyName), keyPEM, 0o600); err != nil {
		return fmt.Errorf("tlsutil: writing private key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, SelfSignedCertName), certPEM, 0o644); err != nil {
		return fmt.Errorf("tlsutil: writing certificate: %w", err)
	}
	return nil
}

// certCovers reports whether the certificate is valid for every name given.
//
// An empty entry is ignored rather than treated as a failure, so that a caller
// passing a not-yet-configured public host does not force endless regeneration.
func certCovers(cert *x509.Certificate, hosts []string) bool {
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			found := false
			for _, have := range cert.IPAddresses {
				if have.Equal(ip) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
			continue
		}
		found := false
		for _, have := range cert.DNSNames {
			if strings.EqualFold(have, h) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Fingerprint returns the lowercase hex SHA-256 of a certificate's DER encoding.
//
// The hex form carries no separators so that it survives being placed in a URI
// query parameter without escaping. DisplayFingerprint renders the same value for
// humans.
func Fingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// DisplayFingerprint renders a fingerprint as colon-separated uppercase byte pairs,
// which is the form users compare against what their client shows.
func DisplayFingerprint(fp string) string {
	fp = strings.ToLower(strings.ReplaceAll(fp, ":", ""))
	if len(fp)%2 != 0 {
		return strings.ToUpper(fp)
	}
	parts := make([]string, 0, len(fp)/2)
	for i := 0; i < len(fp); i += 2 {
		parts = append(parts, strings.ToUpper(fp[i:i+2]))
	}
	return strings.Join(parts, ":")
}

// ServerConfig builds the transport configuration for the relay.
//
// # TLS version floor: 1.2, not 1.3
//
// Pinning TLS 1.3 as the minimum is tempting and was the first thing this code
// did. It is wrong for this project, for a reason that only shows up when you try
// to connect:
//
//   - Android 8.0 and 9.0 — which are exactly the devices minSdk 26 targets — ship
//     a Conscrypt without TLS 1.3.
//   - Windows 10's Schannel has no TLS 1.3 either, so a plain `curl` cannot reach
//     the server at all.
//
// A TLS floor that excludes part of the supported client base is not a security
// improvement; it is an outage. TLS 1.2 restricted to Go's default cipher suites is
// a reasonable floor: every suite Go offers for 1.2 is ECDHE with an AEAD
// (AES-GCM or ChaCha20-Poly1305), so forward secrecy and authenticated encryption
// are both guaranteed, and the CBC and RC4 suites that made 1.2 controversial are
// simply never negotiated. Peers that do support 1.3 — every current Android
// release, and the Go client used in the tests — negotiate it automatically.
//
// The end-to-end encryption does not depend on this decision: the transport
// protects metadata and routing integrity, and SCHAT.md section 11.3 is explicit
// that message content is safe either way.
//
// # HTTP/2 is disabled
//
// NextProtos is pinned to http/1.1 and nothing else. A WebSocket upgrade works by
// hijacking the connection, which HTTP/2 cannot do, so advertising "h2" would let a
// client negotiate a protocol on which /ws could never succeed and then report a
// confusing failure.
func ServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
}

// HostsFor derives the subject alternative names for a deployment.
//
// It always includes localhost and the loopback addresses so that a client on the
// same machine can connect for testing, and adds the configured public host plus
// any detected local addresses so that a LAN client can connect by IP.
func HostsFor(publicHost string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}

	if h := strings.TrimSpace(publicHost); h != "" {
		hosts = append(hosts, h)
	}

	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				hosts = append(hosts, ipnet.IP.String())
			}
		}
	}

	return dedupe(hosts)
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func firstNonEmpty(values []string, fallback string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return fallback
}

// CertFileExists reports whether a usable certificate pair is configured.
func CertFileExists(certFile, keyFile string) bool {
	if certFile == "" || keyFile == "" {
		return false
	}
	if _, err := os.Stat(certFile); err != nil {
		return false
	}
	if _, err := os.Stat(keyFile); err != nil {
		return false
	}
	return true
}
