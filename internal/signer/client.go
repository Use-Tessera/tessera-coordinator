// Package signer is an HTTP client for the tessera/signer/v1 protocol.
package signer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Protocol is the signer protocol this client speaks.
const Protocol = "tessera/signer/v1"

// Info is GET /v1/info.
type Info struct {
	Protocol     string `json:"protocol"`
	Identifier   string `json:"identifier"`
	Account      string `json:"account"`
	Threshold    int    `json:"threshold"`
	Signers      int    `json:"signers"`
	Network      string `json:"network"`
	PolicySHA256 string `json:"policy_sha256"`
}

// Aggregate is POST /v1/aggregate's response.
type Aggregate struct {
	Hash      string `json:"hash"`
	Signature string `json:"signature"`
	Envelope  string `json:"envelope"`
}

// AuthAggregate is POST /v1/aggregate/auth's response.
type AuthAggregate struct {
	Hash      string `json:"hash"`
	Signature string `json:"signature"`
	AuthEntry string `json:"auth_entry"`
}

// RefusedError means the signer's policy rejected the transaction.
type RefusedError struct {
	Signer     string
	Violations []string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("signer %s refused: %s", e.Signer, strings.Join(e.Violations, "; "))
}

// Client talks to one signer.
type Client struct {
	URL   string
	Token string
	HTTP  *http.Client
}

// New returns a client with a per-request timeout.
func New(url, token string) *Client {
	return &Client{URL: strings.TrimRight(url, "/"), Token: token, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

// Info fetches the signer's identity.
func (c *Client) Info(ctx context.Context) (*Info, error) {
	var out Info
	if err := c.do(ctx, http.MethodGet, "/v1/info", nil, &out); err != nil {
		return nil, err
	}
	if out.Protocol != Protocol {
		return nil, fmt.Errorf("signer %s speaks %q, want %q", c.URL, out.Protocol, Protocol)
	}
	return &out, nil
}

// Round1 opens a session and returns (identifier, commitments).
func (c *Client) Round1(ctx context.Context, session string) (string, string, error) {
	var out struct {
		Identifier  string `json:"identifier"`
		Commitments string `json:"commitments"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/round1", map[string]string{"session": session}, &out)
	return out.Identifier, out.Commitments, err
}

// Round2 asks for a signature share over envelope.
func (c *Client) Round2(ctx context.Context, session, envelope string, commitments map[string]string) (string, error) {
	var out struct {
		Share string `json:"share"`
	}
	body := map[string]any{"session": session, "envelope": envelope, "commitments": commitments}
	err := c.do(ctx, http.MethodPost, "/v1/round2", body, &out)
	return out.Share, err
}

// Aggregate combines shares into a signed envelope.
func (c *Client) Aggregate(ctx context.Context, envelope string, commitments, shares map[string]string) (*Aggregate, error) {
	var out Aggregate
	body := map[string]any{"envelope": envelope, "commitments": commitments, "shares": shares}
	if err := c.do(ctx, http.MethodPost, "/v1/aggregate", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Round2Auth asks for a signature share over a Soroban authorization entry.
// latestLedger bounds how long the signer lets the authorization stay valid.
func (c *Client) Round2Auth(ctx context.Context, session, entry string, latestLedger uint32, commitments map[string]string) (string, error) {
	var out struct {
		Share string `json:"share"`
	}
	body := map[string]any{"session": session, "auth_entry": entry, "latest_ledger": latestLedger, "commitments": commitments}
	err := c.do(ctx, http.MethodPost, "/v1/round2/auth", body, &out)
	return out.Share, err
}

// AggregateAuth combines shares into a signed authorization entry.
func (c *Client) AggregateAuth(ctx context.Context, entry string, commitments, shares map[string]string) (*AuthAggregate, error) {
	var out AuthAggregate
	body := map[string]any{"auth_entry": entry, "commitments": commitments, "shares": shares}
	if err := c.do(ctx, http.MethodPost, "/v1/aggregate/auth", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.URL+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("signer %s: %w", c.URL, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("signer %s: %w", c.URL, err)
	}
	if resp.StatusCode == http.StatusOK {
		return json.Unmarshal(data, out)
	}
	var e struct {
		Error      string   `json:"error"`
		Violations []string `json:"violations"`
	}
	_ = json.Unmarshal(data, &e)
	if resp.StatusCode == http.StatusForbidden && len(e.Violations) > 0 {
		return &RefusedError{Signer: c.URL, Violations: e.Violations}
	}
	if e.Error == "" {
		e.Error = http.StatusText(resp.StatusCode)
	}
	return fmt.Errorf("signer %s: %s %s: HTTP %d: %w", c.URL, method, path, resp.StatusCode, errors.New(e.Error))
}
