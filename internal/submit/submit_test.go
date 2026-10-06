package submit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRPC answers sendTransaction with the given statuses in turn, then
// reports the transaction NOT_FOUND `pending` times before final.
func fakeRPC(t *testing.T, sends []string, pending int, final string) (*Client, *atomic.Int32) {
	t.Helper()
	var sent, polled atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var result any
		switch req.Method {
		case "sendTransaction":
			i := int(sent.Add(1)) - 1
			result = map[string]string{"status": sends[min(i, len(sends)-1)], "errorResultXdr": "AAAAAAAAAGT////7AAAAAA=="}
		case "getTransaction":
			if int(polled.Add(1)) <= pending {
				result = map[string]string{"status": "NOT_FOUND"}
			} else {
				result = map[string]any{"status": final, "ledger": 812345}
			}
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": "method not found"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": result})
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL)
	c.Poll = time.Millisecond
	return c, &sent
}

func TestSubmitWaitsForTheOutcome(t *testing.T) {
	c, _ := fakeRPC(t, []string{"PENDING"}, 3, "SUCCESS")
	out, err := c.Submit(context.Background(), "env", "hash")
	if err != nil || out.Status != "SUCCESS" || out.Ledger != 812345 {
		t.Fatal(out, err)
	}
}

func TestDuplicateIsNotAnError(t *testing.T) {
	c, _ := fakeRPC(t, []string{"DUPLICATE"}, 0, "FAILED")
	if out, err := c.Submit(context.Background(), "env", "hash"); err != nil || out.Status != "FAILED" {
		t.Fatal(out, err)
	}
}

func TestRejectionCarriesTheResult(t *testing.T) {
	c, _ := fakeRPC(t, []string{"ERROR"}, 0, "")
	_, err := c.Submit(context.Background(), "env", "hash")
	if err == nil || !strings.Contains(err.Error(), "ERROR AAAAAAAAAGT////7AAAAAA==") {
		t.Fatal(err)
	}
}

func TestSubmitStopsWithTheContext(t *testing.T) {
	c, _ := fakeRPC(t, []string{"PENDING"}, 1<<30, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Submit(ctx, "env", "hash"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
