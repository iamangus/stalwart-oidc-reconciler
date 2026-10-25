package source

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSnapshotSchema(t *testing.T) {
	for i, body := range []string{`{"complete":true,"issuer":"https://id.example.com","scope":"org","users":[]}`, `{"complete":true,"users":[]} trailing`, `{"compelete":true}`, `not-json`} {
		path := filepath.Join(t.TempDir(), "users.json")
		_ = os.WriteFile(path, []byte(body), 0600)
		s, err := (File{Path: path}).Snapshot(context.Background())
		if i == 0 {
			if err != nil || !s.Complete {
				t.Fatal(err)
			}
		} else if err == nil {
			t.Fatal("bad source accepted", body)
		}
	}
}
