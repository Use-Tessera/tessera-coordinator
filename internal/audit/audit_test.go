package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChainSurvivesReopenAndDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []string{"signed", "refused"} {
		if _, err := l.Append(Record{Time: time.Unix(1, 0).UTC(), TxHash: "aa", Outcome: outcome}); err != nil {
			t.Fatal(err)
		}
	}
	l, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := l.Append(Record{Outcome: "signed"}); err != nil || r.Seq != 3 {
		t.Fatalf("append after reopen: seq %d, %v", r.Seq, err)
	}

	data, _ := os.ReadFile(path)
	cases := map[string]string{
		"edited":  strings.Replace(string(data), `"refused"`, `"signed"`, 1),
		"deleted": strings.Join(append(strings.SplitN(string(data), "\n", 3)[:1], strings.SplitN(string(data), "\n", 3)[2]), "\n"),
	}
	for name, tampered := range cases {
		p := filepath.Join(t.TempDir(), name+".jsonl")
		_ = os.WriteFile(p, []byte(tampered), 0o600)
		if _, err := Open(p); err == nil {
			t.Errorf("%s log was accepted", name)
		}
	}
}
