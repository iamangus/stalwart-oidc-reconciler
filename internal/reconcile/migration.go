package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/identity"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/mailbox"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/state"
)

type OwnershipMapping struct {
	FromID    string `json:"from_id"`
	ToID      string `json:"to_id"`
	AccountID string `json:"account_id"`
	Address   string `json:"address"`
	Status    string `json:"status"`
}

type ProtectedMapping struct {
	IdentityID string `json:"identity_id"`
	AccountID  string `json:"account_id"`
	Address    string `json:"address"`
	Status     string `json:"status"`
}

// Migration is a complete, explicit disposition of existing ownership. It does
// not discover mappings by name/email or mutate accounts in either directory.
type Migration struct {
	FromFingerprint string             `json:"from_fingerprint"`
	ToFingerprint   string             `json:"to_fingerprint"`
	Mappings        []OwnershipMapping `json:"mappings"`
	Protect         []ProtectedMapping `json:"protect"`
}

func LoadMigration(path string) (Migration, error) {
	var m Migration
	f, err := os.Open(path)
	if err != nil {
		return m, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return m, errors.New("migration is malformed or contains unsupported fields")
	}
	return m, nil
}

func (e *Engine) BuildMigration(previous state.Data, m Migration, src identity.Snapshot, dest mailbox.Snapshot, now time.Time) (Plan, error) {
	fail := func() (Plan, error) {
		return Plan{}, errors.New("migration fingerprint, identity or complete ownership disposition does not match")
	}
	if m.FromFingerprint == "" || m.ToFingerprint == "" || m.FromFingerprint == m.ToFingerprint ||
		m.ToFingerprint != e.Policy.Fingerprint() || len(m.Mappings) == 0 ||
		len(m.Mappings)+len(m.Protect) != len(previous.Entries) {
		return fail()
	}
	already := previous.Fingerprint == m.ToFingerprint
	if !already && previous.Fingerprint != m.FromFingerprint {
		return fail()
	}
	next := clone(previous)
	entries := next.Entries
	next.Entries = map[string]*state.Entry{}
	next.Fingerprint = m.ToFingerprint
	seenOld, seenNew := map[string]bool{}, map[string]bool{}
	sourceIDs := map[string]bool{}
	for _, u := range src.Users {
		if u.Human && u.Active {
			sourceIDs[u.ID] = true
		}
	}
	for _, mapping := range m.Mappings {
		key := mapping.FromID
		if already {
			key = mapping.ToID
		}
		entry := entries[key]
		if mapping.FromID == "" || mapping.ToID == "" || seenOld[mapping.FromID] || seenNew[mapping.ToID] || !sourceIDs[mapping.ToID] ||
			entry == nil || entry.Protected || entry.Transition != "" || entry.AccountID != mapping.AccountID || entry.Address != mapping.Address ||
			entry.Status != mapping.Status || mapping.Status != "active" {
			return fail()
		}
		seenOld[mapping.FromID], seenNew[mapping.ToID] = true, true
		next.Entries[mapping.ToID] = entry
	}
	for _, mapping := range m.Protect {
		entry := entries[mapping.IdentityID]
		if mapping.IdentityID == "" || seenOld[mapping.IdentityID] || seenNew[mapping.IdentityID] || entry == nil || entry.Transition != "" ||
			entry.AccountID != mapping.AccountID || entry.Address != mapping.Address || entry.Status != mapping.Status ||
			(entry.Status != "active" && entry.Status != "suspended") || (already && !entry.Protected) {
			return fail()
		}
		seenOld[mapping.IdentityID], seenNew[mapping.IdentityID] = true, true
		entry.Protected = true
		next.Entries[mapping.IdentityID] = entry
	}
	if len(next.Entries) != len(previous.Entries) {
		return fail()
	}
	plan, err := e.Build(src, dest, next, now)
	if err != nil {
		return Plan{}, err
	}
	if len(plan.Actions) != 0 {
		return Plan{}, errors.New("migration would require mailbox mutations; review and resolve the separate reconciliation plan first")
	}
	return plan, nil
}

// Migrate requires the same exclusive state lock as normal reconciliation. A
// dry run does not write state. Neither mode invokes Target.Create/Update.
func (e *Engine) Migrate(ctx context.Context, m Migration, apply bool) (Plan, error) {
	previous, err := e.Store.Load()
	if err != nil {
		return Plan{}, err
	}
	src, err := e.Source.Snapshot(ctx)
	if err != nil {
		return Plan{}, err
	}
	dest, err := e.Target.Snapshot(ctx)
	if err != nil {
		return Plan{}, err
	}
	now := time.Now().UTC()
	if e.Now != nil {
		now = e.Now().UTC()
	}
	plan, err := e.BuildMigration(previous, m, src, dest, now)
	if err != nil || !apply {
		return plan, err
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	return plan, e.Store.Save(plan.Next)
}
