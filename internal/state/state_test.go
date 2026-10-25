package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLockAtomicRoundTripAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("second writer acquired lock")
	}
	d, err := f.Load()
	if err != nil || len(d.Entries) != 0 {
		t.Fatal(err)
	}
	d.Fingerprint = "fingerprint"
	d.Entries["alice"] = &Entry{AccountID: "1", Address: "alice.example@example.com", Status: "active"}
	if err := f.Save(d); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil || got.Entries["alice"].AccountID != "1" {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

func TestCorruptStateIsNotAnEmptyInventory(t *testing.T) {
	for _, text := range []string{`{}`, `not json`, `{"version":2,"fingerprint":"x","entries":{}}`, `{"version":1,"fingerprint":"x","entries":{}} trailing`, `{"version":1,"fingerprint":"x","entries":{"a":{"account_id":"1","address":"a@example.com","status":"active"},"b":{"account_id":"1","address":"b@example.com","status":"active"}}}`} {
		path := filepath.Join(t.TempDir(), "state.json")
		_ = os.WriteFile(path, []byte(text), 0600)
		if _, err := Read(path); err == nil {
			t.Fatal("corrupt state accepted", text)
		}
	}
}
