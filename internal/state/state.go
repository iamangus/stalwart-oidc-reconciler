// Package state persists ownership, stable address allocation, and write-ahead
// creation intent. State is operational data: back it up alongside mailboxes.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type Entry struct {
	AccountID           string          `json:"account_id,omitempty"`
	Address             string          `json:"address"`
	Status              string          `json:"status"` // active, suspended, pending
	MissingSince        *time.Time      `json:"missing_since,omitempty"`
	PreviousPermissions json.RawMessage `json:"previous_permissions,omitempty"`
	Transition          string          `json:"transition,omitempty"`
}

type Data struct {
	Version      int               `json:"version"`
	Fingerprint  string            `json:"fingerprint"`
	LastComplete time.Time         `json:"last_complete"`
	Entries      map[string]*Entry `json:"entries"`
}

type Store interface {
	Load() (Data, error)
	Save(Data) error
}

type File struct {
	Path string
	lock *os.File
}

func Open(path string) (*File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another reconciler holds this state lock")
	}
	return &File{Path: path, lock: f}, nil
}

func (f *File) Close() error { return f.lock.Close() }

func Read(path string) (Data, error) {
	var d Data
	h, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Data{Version: 1, Entries: map[string]*Entry{}}, nil
	}
	if err != nil {
		return d, err
	}
	defer h.Close()
	decoder := json.NewDecoder(io.LimitReader(h, 16<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF {
		return d, errors.New("state is corrupt or has unsupported fields; refusing to start")
	}
	if d.Version != 1 || d.Entries == nil || d.Fingerprint == "" {
		return d, errors.New("unsupported or incomplete state")
	}
	ids := map[string]bool{}
	addresses := map[string]bool{}
	for key, entry := range d.Entries {
		if entry == nil || key == "" || entry.Address == "" || addresses[entry.Address] {
			return d, errors.New("invalid or duplicate state entry")
		}
		addresses[entry.Address] = true
		if entry.Status != "pending" && entry.Status != "active" && entry.Status != "suspended" {
			return d, errors.New("unknown state entry status")
		}
		if entry.Transition != "" && entry.Transition != "suspend" && entry.Transition != "resume" {
			return d, errors.New("unknown state permission transition")
		}
		if entry.AccountID != "" {
			if ids[entry.AccountID] {
				return d, errors.New("duplicate owned Stalwart account ID")
			}
			ids[entry.AccountID] = true
		} else if entry.Status != "pending" {
			return d, errors.New("owned state entry is missing Stalwart ID")
		}
	}
	return d, nil
}

func (f *File) Load() (Data, error) { return Read(f.Path) }

func (f *File) Save(d Data) (err error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".reconciler-state-*")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(append(b, '\n'))
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), f.Path)
	}
	if err != nil {
		return fmt.Errorf("persist state: %w", err)
	}
	dir, err := os.Open(filepath.Dir(f.Path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
