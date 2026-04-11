package chain

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustMakeDER generates a minimal self-signed DER certificate for testing.
func mustMakeDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

func TestIsSelfSigned(t *testing.T) {
	der := mustMakeDER(t)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.False(t, isSelfSigned(cert), "minimal non-CA cert is not treated as a trust root")

	// Issued by a different CA (not self-signed).
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	eeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	eeTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "ee"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	eeDER, err := x509.CreateCertificate(rand.Reader, eeTmpl, caTmpl, &eeKey.PublicKey, caKey)
	require.NoError(t, err)
	eeCert, err := x509.ParseCertificate(eeDER)
	require.NoError(t, err)
	assert.False(t, isSelfSigned(eeCert))

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	assert.True(t, isSelfSigned(caCert))
}

func TestFetchRemoteCert(t *testing.T) {
	tests := []struct {
		name        string
		handler     http.HandlerFunc
		cancelCtx   bool
		wantErr     bool
		errContains string
	}{
		{
			name: "success: DER certificate returned",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write(mustMakeDER(t)) //nolint:errcheck
			},
			wantErr: false,
		},
		{
			name: "http 404 returns error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.NotFound(w, r)
			},
			wantErr:     true,
			errContains: "http error",
		},
		{
			name: "empty body returns no certificate error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			wantErr:     true,
			errContains: "no certificate found",
		},
		{
			name: "garbage body returns no certificate error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF}) //nolint:errcheck
			},
			wantErr:     true,
			errContains: "no certificate found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			ctx := context.Background()
			cert, err := fetchRemoteCert(ctx, srv.URL)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.ErrorContains(t, err, tc.errContains)
				}
				assert.Nil(t, cert)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cert)
			}
		})
	}
}

func TestFetchRemoteCert_ContextCancelled(t *testing.T) {
	// Server that blocks until the request context is done.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately before the call

	_, err := fetchRemoteCert(ctx, srv.URL)
	require.Error(t, err)
	assert.ErrorIs(t, ctx.Err(), context.Canceled)
}
