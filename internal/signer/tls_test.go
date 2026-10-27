package signer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Use-Tessera/tessera-coordinator/internal/signer"
)

type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pair tls.Certificate
}

// issue makes a certificate signed by parent (self-signed when parent is nil).
func issue(t *testing.T, name string, parent *issued, usage x509.ExtKeyUsage) *issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	signer, signerKey := tmpl, key
	if parent == nil {
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{usage}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &issued{cert: cert, key: key, pair: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}
}

// tlsSigner serves GET /v1/info over TLS, requiring client certificates from ca.
func tlsSigner(t *testing.T, ca *issued) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(signer.Info{Protocol: signer.Protocol, Identifier: "01"})
	}))
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{issue(t, "signer", ca, x509.ExtKeyUsageServerAuth).pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func clientTLS(ca *issued, client *issued) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if client != nil {
		cfg.Certificates = []tls.Certificate{client.pair}
	}
	return cfg
}

func TestMutualTLSWithAClientCertificate(t *testing.T) {
	ca := issue(t, "ca", nil, 0)
	srv := tlsSigner(t, ca)
	coordinator := issue(t, "coordinator", ca, x509.ExtKeyUsageClientAuth)
	info, err := signer.NewTLS(srv.URL, "", clientTLS(ca, coordinator)).Info(context.Background())
	if err != nil || info.Identifier != "01" {
		t.Fatalf("want the signer's info, got %+v, %v", info, err)
	}
}

func TestMutualTLSRefusesAClientWithoutACertificate(t *testing.T) {
	ca := issue(t, "ca", nil, 0)
	srv := tlsSigner(t, ca)
	if _, err := signer.NewTLS(srv.URL, "", clientTLS(ca, nil)).Info(context.Background()); err == nil {
		t.Fatal("a client without a certificate was served")
	}
}

func TestMutualTLSRefusesASignerFromAnotherCA(t *testing.T) {
	ca := issue(t, "ca", nil, 0)
	srv := tlsSigner(t, ca)
	other := issue(t, "other ca", nil, 0)
	coordinator := issue(t, "coordinator", ca, x509.ExtKeyUsageClientAuth)
	// The coordinator trusts only `other` for signers, so it refuses this one.
	if _, err := signer.NewTLS(srv.URL, "", clientTLS(other, coordinator)).Info(context.Background()); err == nil {
		t.Fatal("trusted a signer certificate from a CA it was not given")
	}
}
