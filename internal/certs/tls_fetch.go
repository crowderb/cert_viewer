package certs

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// ParseHostPort extracts a host and port from a raw user input string.
// Accepts bare hostnames ("example.com"), host:port pairs ("example.com:8443"),
// and HTTPS URLs ("https://example.com" or "https://example.com:8443").
// Defaults to port "443" when no port is specified.
func ParseHostPort(rawInput string) (host, port string, err error) {
	input := strings.TrimSpace(rawInput)
	if input == "" {
		return "", "", fmt.Errorf("host is required")
	}

	// Full URL (contains a scheme separator)
	if strings.Contains(input, "://") {
		u, parseErr := url.Parse(input)
		if parseErr != nil {
			return "", "", fmt.Errorf("invalid URL: %w", parseErr)
		}
		h := u.Hostname()
		if h == "" {
			return "", "", fmt.Errorf("no host found in URL")
		}
		p := u.Port()
		if p == "" {
			p = "443"
		}
		return h, p, nil
	}

	// host:port pair
	if h, p, splitErr := net.SplitHostPort(input); splitErr == nil {
		if h == "" {
			return "", "", fmt.Errorf("host is required")
		}
		return h, p, nil
	}

	// Bare hostname (no port)
	return input, "443", nil
}

// FetchTLSCerts dials host:port via TLS and returns the certificates presented
// by the server (PeerCertificates). When skipVerify is true, certificate
// verification errors (expired, self-signed, unknown CA) are ignored so the
// certificates can still be inspected. Returns at least one certificate or an
// error.
func FetchTLSCerts(rawInput string, skipVerify bool) ([]*x509.Certificate, error) {
	host, port, err := ParseHostPort(rawInput)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":"+port, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: skipVerify, //nolint:gosec // intentional for cert inspection
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection to %s:%s failed: %w", host, port, err)
	}
	defer func() { _ = conn.Close() }()

	peerCerts := conn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return nil, fmt.Errorf("no certificates returned by %s:%s", host, port)
	}
	return peerCerts, nil
}
