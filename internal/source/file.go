package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/httpapi"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/identity"
)

// File is a second provider-independent adapter, useful for declarative user
// inventories and external exporters. Writers must atomically replace the file.
type File struct{ Path string }

func (f File) Snapshot(ctx context.Context) (identity.Snapshot, error) {
	var snapshot identity.Snapshot
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	h, err := os.Open(f.Path)
	if err != nil {
		return snapshot, err
	}
	defer h.Close()
	b, err := io.ReadAll(io.LimitReader(h, httpapi.MaxBody+1))
	if err != nil || len(b) > httpapi.MaxBody {
		return snapshot, errors.New("identity file unreadable or too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&snapshot); err != nil {
		return snapshot, errors.New("identity file has invalid schema")
	}
	if d.Decode(new(any)) != io.EOF {
		return snapshot, errors.New("identity file contains trailing data")
	}
	return snapshot, nil
}
