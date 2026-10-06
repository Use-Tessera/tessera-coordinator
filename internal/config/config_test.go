package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "coordinator.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const valid = `
network = "testnet"
audit_log = "audit.jsonl"

[[signer]]
url = "http://127.0.0.1:7501"

[[signer]]
url = "http://127.0.0.1:7502"
token_env = "SIGNER_2_TOKEN"
`

func TestLoadAppliesDefaults(t *testing.T) {
	p := write(t, valid)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:7400" {
		t.Errorf("listen = %q", c.Listen)
	}
	if c.AuditLog != filepath.Join(filepath.Dir(p), "audit.jsonl") {
		t.Errorf("audit_log not resolved next to the config: %q", c.AuditLog)
	}
	if c.Passphrase() != "Test SDF Network ; September 2015" {
		t.Errorf("passphrase = %q", c.Passphrase())
	}
	if len(c.Signers) != 2 || c.Signers[1].TokenEnv != "SIGNER_2_TOKEN" {
		t.Errorf("signers = %+v", c.Signers)
	}
}

func TestCustomPassphrasePassesThrough(t *testing.T) {
	c := Config{Network: "Standalone Network ; February 2017"}
	if c.Passphrase() != c.Network {
		t.Fatal(c.Passphrase())
	}
}

func TestLoadRejects(t *testing.T) {
	for name, c := range map[string]struct{ body, want string }{
		"unknown key":    {valid + "\nlisten_port = 1\n", "unknown keys"},
		"no network":     {strings.Replace(valid, `network = "testnet"`, "", 1), "network is required"},
		"no audit log":   {strings.Replace(valid, `audit_log = "audit.jsonl"`, "", 1), "audit_log is required"},
		"one signer":     {"network = \"testnet\"\naudit_log = \"a\"\n[[signer]]\nurl = \"x\"\n", "two [[signer]]"},
		"malformed toml": {"network = ", ""},
	} {
		_, err := Load(write(t, c.body))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

func TestEnv(t *testing.T) {
	t.Setenv("TESSERA_TEST_TOKEN", "s3cret")
	if v, err := Env("TESSERA_TEST_TOKEN"); err != nil || v != "s3cret" {
		t.Fatal(v, err)
	}
	if v, err := Env(""); err != nil || v != "" {
		t.Fatal("an unset name means no token", v, err)
	}
	if _, err := Env("TESSERA_TEST_UNSET_TOKEN"); err == nil {
		t.Fatal("a named but empty variable must fail")
	}
}
