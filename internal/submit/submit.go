// Package submit sends signed transactions through Stellar RPC and waits for the outcome.
package submit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Outcome of a submitted transaction.
type Outcome struct {
	Status string `json:"status"` // SUCCESS or FAILED
	Ledger uint32 `json:"ledger,omitempty"`
}

// Client submits through one RPC endpoint.
type Client struct {
	URL  string
	HTTP *http.Client
	Poll time.Duration
}

// New returns a client that polls once a second.
func New(url string) *Client {
	return &Client{URL: url, HTTP: &http.Client{Timeout: 20 * time.Second}, Poll: time.Second}
}

// Submit sends the envelope and waits until the network applies or rejects it.
func (c *Client) Submit(ctx context.Context, envelope, hash string) (*Outcome, error) {
	var sent struct {
		Status         string `json:"status"`
		ErrorResultXDR string `json:"errorResultXdr"`
	}
	for attempt := 0; ; attempt++ {
		if err := c.call(ctx, "sendTransaction", map[string]string{"transaction": envelope}, &sent); err != nil {
			return nil, err
		}
		// TRY_AGAIN_LATER means the node's queue is full; the transaction
		// was not accepted, so sending it again is safe.
		if sent.Status != "TRY_AGAIN_LATER" || attempt == maxResends {
			break
		}
		if err := sleep(ctx, c.Poll); err != nil {
			return nil, fmt.Errorf("resending %s: %w", hash, err)
		}
	}
	switch sent.Status {
	case "PENDING", "DUPLICATE":
	default:
		return nil, fmt.Errorf("sendTransaction: %s %s", sent.Status, sent.ErrorResultXDR)
	}
	for {
		var got struct {
			Status string `json:"status"`
			Ledger uint32 `json:"ledger"`
		}
		if err := c.call(ctx, "getTransaction", map[string]string{"hash": hash}, &got); err != nil {
			return nil, err
		}
		if got.Status == "SUCCESS" || got.Status == "FAILED" {
			return &Outcome{Status: got.Status, Ledger: got.Ledger}, nil
		}
		if err := sleep(ctx, c.Poll); err != nil {
			return nil, fmt.Errorf("waiting for %s: %w", hash, err)
		}
	}
}

// maxResends bounds how often a TRY_AGAIN_LATER answer is retried.
const maxResends = 10

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) call(ctx context.Context, method string, params, out any) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tessera-coordinator")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	defer resp.Body.Close()
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	if env.Error != nil {
		return fmt.Errorf("%s: %s", method, env.Error.Message)
	}
	return json.Unmarshal(env.Result, out)
}
