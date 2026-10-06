// Package config loads coordinator.toml.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// Signer is one [[signer]] entry.
type Signer struct {
	URL      string `toml:"url"`
	TokenEnv string `toml:"token_env"`
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
	if !filepath.IsAbs(c.AuditLog) {
		c.AuditLog = filepath.Join(filepath.Dir(path), c.AuditLog)
	}
	return &c, nil
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
