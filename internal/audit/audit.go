// Package audit keeps a tamper-evident, append-only log of signing decisions.
//
// Each record carries the SHA-256 of the previous record, so editing,
// reordering or deleting any line breaks the chain from that point on.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Record is one signing attempt.
type Record struct {
	Seq       uint64              `json:"seq"`
	Time      time.Time           `json:"time"`
	Session   string              `json:"session"`
	Kind      string              `json:"kind,omitempty"` // transaction | authorization
	TxHash    string              `json:"tx_hash"`        // or the authorization payload hash
	Outcome   string              `json:"outcome"`        // signed | refused | failed
	Signers   []string            `json:"signers,omitempty"`
	Refusals  map[string][]string `json:"refusals,omitempty"`
	Error     string              `json:"error,omitempty"`
	Submitted string              `json:"submitted,omitempty"`
	Prev      string              `json:"prev"`
	Hash      string              `json:"hash"`
}

// Log appends records to a JSON-lines file.
type Log struct {
	mu   sync.Mutex
	path string
	seq  uint64
	last string
}

const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Open opens or creates a log, verifying the existing chain first.
func Open(path string) (*Log, error) {
	l := &Log{path: path, last: genesis}
	recs, err := Read(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := Verify(recs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if n := len(recs); n > 0 {
		l.seq, l.last = recs[n-1].Seq, recs[n-1].Hash
	}
	return l, nil
}

// Append chains r onto the log and writes it durably.
func (l *Log) Append(r Record) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r.Seq = l.seq + 1
	r.Prev = l.last
	r.Hash = ""
	h, err := digest(r)
	if err != nil {
		return r, err
	}
	r.Hash = h
	line, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return r, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return r, err
	}
	if err := f.Sync(); err != nil {
		return r, err
	}
	l.seq, l.last = r.Seq, r.Hash
	return r, nil
}

// Read loads every record in a log file.
func Read(path string) ([]Record, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the audit log
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("line %d: %w", len(out)+1, err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// Verify checks sequence numbers and the hash chain.
func Verify(recs []Record) error {
	prev := genesis
	for i, r := range recs {
		if r.Seq != uint64(i+1) {
			return fmt.Errorf("record %d: sequence %d out of order", i+1, r.Seq)
		}
		if r.Prev != prev {
			return fmt.Errorf("record %d: chain broken (prev does not match)", r.Seq)
		}
		claimed := r.Hash
		r.Hash = ""
		h, err := digest(r)
		if err != nil {
			return err
		}
		if h != claimed {
			return fmt.Errorf("record %d: contents do not match its hash", r.Seq)
		}
		prev = claimed
	}
	return nil
}

func digest(r Record) (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
