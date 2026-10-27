// Package config loads coordinator.toml.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Signer is one [[signer]] entry.
type Signer struct {
	URL      string `toml:"url"`
	TokenEnv string `toml:"token_env"`
	// CA overrides [tls].ca for this signer (PEM).
	CA string `toml:"ca"`
}

// TLS is [tls]: mutual TLS to the signers. Files are PEM.
type TLS struct {
	Cert string `toml:"cert"` // the coordinator's client certificate chain
	Key  string `toml:"key"`  // its private key
	CA   string `toml:"ca"`   // CA certificates that issue the signers' certificates
}

// Config is coordinator.toml.
type Config struct {
	Listen      string `toml:"listen"`
	Network     string `toml:"network"`
	RPC         string `toml:"rpc"`
	AuditLog    string `toml:"audit_log"`
	APITokenEnv string `toml:"api_token_env"`
	// SessionTimeout bounds one signing session, both rounds included.
	SessionTimeout Duration `toml:"session_timeout"`
	Signers        []Signer `toml:"signer"`
	// TLS, when set, makes every signer connection mutual TLS.
	TLS *TLS `toml:"tls"`
}

// Duration is a TOML string such as "20s".
type Duration struct{ time.Duration }

// UnmarshalText parses a Go duration.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

var networks = map[string]string{
	"public":  "Public Global Stellar Network ; September 2015",
	"mainnet": "Public Global Stellar Network ; September 2015",
	"testnet": "Test SDF Network ; September 2015",
}

// Passphrase resolves the network name.
func (c *Config) Passphrase() string {
	if p, ok := networks[c.Network]; ok {
		return p
	}
	return c.Network
}

// Load reads and validates a config file. audit_log is resolved relative to it.
func Load(path string) (*Config, error) {
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("%s: unknown keys %v", path, und)
	}
	switch {
	case c.Network == "":
		return nil, fmt.Errorf("%s: network is required", path)
	case len(c.Signers) < 2:
		return nil, fmt.Errorf("%s: at least two [[signer]] entries are required", path)
	case c.AuditLog == "":
		return nil, fmt.Errorf("%s: audit_log is required", path)
	case c.SessionTimeout.Duration < 0 || c.SessionTimeout.Duration > 5*time.Minute:
		return nil, fmt.Errorf("%s: session_timeout must be between 0 and 5m", path)
	}
	if c.SessionTimeout.Duration == 0 {
		c.SessionTimeout.Duration = 20 * time.Second
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:7400"
	}
	rel := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(path), *p)
		}
	}
	rel(&c.AuditLog)
	if c.TLS != nil {
		if c.TLS.Cert == "" || c.TLS.Key == "" || c.TLS.CA == "" {
			return nil, fmt.Errorf("%s: [tls] needs cert, key and ca", path)
		}
		rel(&c.TLS.Cert)
		rel(&c.TLS.Key)
		rel(&c.TLS.CA)
	}
	for i := range c.Signers {
		s := &c.Signers[i]
		rel(&s.CA)
		switch {
		case c.TLS != nil && !strings.HasPrefix(s.URL, "https://"):
			return nil, fmt.Errorf("%s: [tls] is set but signer %s is not https://", path, s.URL)
		case c.TLS == nil && s.CA != "":
			return nil, fmt.Errorf("%s: signer %s sets ca without [tls]", path, s.URL)
		}
	}
	return &c, nil
}

// ClientTLS returns the TLS configuration for signer i: the coordinator's
// client certificate, and the CA that must have issued the signer's
// certificate. It is nil when [tls] is not set.
func (c *Config) ClientTLS(i int) (*tls.Config, error) {
	if c.TLS == nil {
		return nil, nil
	}
	pair, err := tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("[tls] client certificate: %w", err)
	}
	caFile := c.TLS.CA
	if c.Signers[i].CA != "" {
		caFile = c.Signers[i].CA
	}
	pem, err := os.ReadFile(caFile) //nolint:gosec // G304: the operator names the CA file
	if err != nil {
		return nil, fmt.Errorf("[tls] ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("[tls] ca: %s holds no PEM certificate", caFile)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// Env reads a required environment variable named by the config.
func Env(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("$%s is empty", name)
	}
	return v, nil
}
