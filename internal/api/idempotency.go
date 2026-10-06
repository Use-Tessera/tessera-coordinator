package api

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net/http"
	"sync"
	"time"
)

// Idempotency replays the response to a repeated request carrying the same
// Idempotency-Key, so a client retrying after a timeout does not start a
// second signing session. That matters because signers count spend when they
// approve: a retried payment would otherwise use the daily limit twice.
//
// Keys are scoped to the route and kept for TTL. A request that reuses a key
// with a different body is rejected. Server errors (5xx) are not remembered,
// so a genuinely failed request can be retried under the same key.
type Idempotency struct {
	TTL time.Duration
	Max int

	mu      sync.Mutex
	entries map[string]*entry
	order   []string // insertion order, for eviction
}

type entry struct {
	done    chan struct{} // closed once the first request has finished
	body    [32]byte      // SHA-256 of the request body
	status  int
	header  http.Header
	payload []byte
	at      time.Time
	keep    bool
}

const maxKeyLen = 128

func (c *Idempotency) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		if key == "" {
			next(w, r)
			return
		}
		if len(key) > maxKeyLen {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key is longer than 128 characters"})
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body too large"})
			return
		}
		sum := sha256.Sum256(raw)
		id := r.URL.Path + "\x00" + key

		e, first := c.claim(id, sum)
		if !first {
			<-e.done
			switch {
			case e.body != sum:
				writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "Idempotency-Key was already used with a different request"})
			case !e.keep:
				// The first attempt failed with a server error and was forgotten; try again.
				c.retry(w, r, id, sum, raw, next)
			default:
				replay(w, e)
			}
			return
		}
		c.run(w, r, id, e, raw, next)
	}
}

// claim returns the entry for id, creating it (first = true) if absent or expired.
func (c *Idempotency) claim(id string, sum [32]byte) (*entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]*entry{}
	}
	if e, ok := c.entries[id]; ok && time.Since(e.at) < c.TTL {
		return e, false
	}
	e := &entry{done: make(chan struct{}), body: sum, at: time.Now()}
	c.entries[id] = e
	c.order = append(c.order, id)
	for len(c.order) > c.Max {
		delete(c.entries, c.order[0])
		c.order = c.order[1:]
	}
	return e, true
}

func (c *Idempotency) run(w http.ResponseWriter, r *http.Request, id string, e *entry, raw []byte, next http.HandlerFunc) {
	rec := &capture{ResponseWriter: w, status: http.StatusOK}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	defer func() {
		e.status, e.header, e.payload = rec.status, rec.Header().Clone(), rec.buf.Bytes()
		e.keep = rec.status < 500
		if !e.keep {
			c.mu.Lock()
			if c.entries[id] == e {
				delete(c.entries, id)
			}
			c.mu.Unlock()
		}
		close(e.done)
	}()
	next(rec, r)
}

func (c *Idempotency) retry(w http.ResponseWriter, r *http.Request, id string, sum [32]byte, raw []byte, next http.HandlerFunc) {
	e, first := c.claim(id, sum)
	if !first {
		<-e.done
		if e.body != sum {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "Idempotency-Key was already used with a different request"})
			return
		}
		replay(w, e)
		return
	}
	c.run(w, r, id, e, raw, next)
}

func replay(w http.ResponseWriter, e *entry) {
	for k, v := range e.header {
		w.Header()[k] = v
	}
	w.Header().Set("Idempotent-Replayed", "true")
	w.WriteHeader(e.status)
	_, _ = w.Write(e.payload)
}

type capture struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (c *capture) WriteHeader(status int) {
	c.status = status
	c.ResponseWriter.WriteHeader(status)
}

func (c *capture) Write(b []byte) (int, error) {
	c.buf.Write(b)
	return c.ResponseWriter.Write(b)
}
