// Package reconcile owns the provider-independent, non-destructive reconciliation
// engine. No account is adopted by email, renamed automatically, or deleted.
package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/identity"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/mailbox"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/state"
)

// Suspended accounts retain mail reception but lose every interactive/API
// permission, not just permission to perform a new authentication.
var SuspendedPermissions = json.RawMessage(`{"@type":"Replace","enabledPermissions":{"emailReceive":true},"disabledPermissions":{"authenticate":true}}`)

type Policy struct {
	Issuer             string
	Scope              string
	SourceKind         string
	Destination        string
	Domain             string
	DomainID           string
	QuotaBytes         int64
	MaxUsers           int
	MissingGrace       time.Duration
	MaxSuspensions     int
	MaxSuspendFraction float64
	AllowEmpty         bool
	ExcludeIDs         []string
	AddressOverrides   map[string]string
}

func (p Policy) Fingerprint() string {
	// Changing a safety scope must never turn the old users into "deleted" users.
	b, _ := json.Marshal([]string{"v1", p.SourceKind, p.Issuer, p.Scope, p.Destination, p.Domain, p.DomainID})
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type Action struct {
	Kind       string          `json:"kind"`
	IdentityID string          `json:"identity_id"`
	Address    string          `json:"address"`
	Reason     string          `json:"reason,omitempty"`
	Patch      map[string]any  `json:"-"`
	Current    mailbox.Account `json:"-"`
}

type Plan struct {
	Actions []Action   `json:"actions"`
	Applied int        `json:"applied"`
	Users   int        `json:"eligible_users"`
	Managed int        `json:"managed_accounts"`
	At      time.Time  `json:"at"`
	Next    state.Data `json:"-"`
}

type Engine struct {
	Source identity.Source
	Target mailbox.Destination
	Store  state.Store
	Policy Policy
	Now    func() time.Time
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	var left, right any
	return json.Unmarshal(x, &left) == nil && json.Unmarshal(y, &right) == nil && reflect.DeepEqual(left, right)
}

func clone(d state.Data) state.Data {
	b, _ := json.Marshal(d)
	var copy state.Data
	_ = json.Unmarshal(b, &copy)
	return copy
}

func (e *Engine) Build(s identity.Snapshot, dest mailbox.Snapshot, previous state.Data, now time.Time) (Plan, error) {
	p := e.Policy
	plan := Plan{At: now, Actions: []Action{}, Managed: len(previous.Entries), Next: clone(previous)}
	fail := func(err error) (Plan, error) { return Plan{}, err }
	if err := s.Validate(p.Issuer, p.Scope, p.MaxUsers); err != nil {
		return fail(err)
	}
	if previous.Fingerprint != "" && previous.Fingerprint != p.Fingerprint() {
		return fail(errors.New("state scope changed; use a separate state file or perform a reviewed migration"))
	}
	plan.Next.Fingerprint = p.Fingerprint()
	plan.Next.Version = 1
	if plan.Next.Entries == nil {
		plan.Next.Entries = map[string]*state.Entry{}
	}
	accounts := map[string]mailbox.Account{}
	usedAddresses := map[string]string{}
	reserve := func(addr, owner string) error {
		if previous := usedAddresses[addr]; previous != "" && previous != owner {
			return errors.New("destination contains an ambiguous mailbox/alias address")
		}
		usedAddresses[addr] = owner
		return nil
	}
	for _, a := range dest.Accounts {
		if a.ID == "" || accounts[a.ID].ID != "" {
			return fail(errors.New("destination contains empty or duplicate account IDs"))
		}
		accounts[a.ID] = a
		if a.DomainID == p.DomainID {
			if err := reserve(strings.ToLower(a.Name)+"@"+p.Domain, a.ID); err != nil {
				return fail(err)
			}
		}
		for _, alias := range a.Aliases {
			// Reserve disabled aliases as well: never recycle someone else's address.
			if alias.DomainID == p.DomainID {
				if err := reserve(strings.ToLower(alias.Name)+"@"+p.Domain, a.ID); err != nil {
					return fail(err)
				}
			}
		}
	}
	excluded := map[string]bool{}
	for _, id := range p.ExcludeIDs {
		excluded[id] = true
	}
	users := map[string]identity.User{}
	for _, user := range s.Users {
		if user.Human && !excluded[user.ID] {
			users[user.ID] = user
		}
	}
	plan.Users = len(users)
	if len(users) == 0 && !p.AllowEmpty {
		return fail(errors.New("empty eligible directory blocked; set allow_empty only after reviewing the source"))
	}
	// Keep retired address reservations forever, even while retaining a mailbox.
	ownedIDs := map[string]bool{}
	for id, entry := range plan.Next.Entries {
		if entry.Status == "pending" || entry.AccountID == "" {
			return fail(fmt.Errorf("identity %s has uncertain creation intent; inspect destination and recover state manually", id))
		}
		if ownedIDs[entry.AccountID] {
			return fail(errors.New("state contains duplicate mailbox ownership"))
		}
		ownedIDs[entry.AccountID] = true
		a, ok := accounts[entry.AccountID]
		if !ok {
			return fail(errors.New("owned mailbox is missing; refusing automatic recreation"))
		}
		if a.Type != "User" || a.DomainID != p.DomainID || a.Name+"@"+p.Domain != entry.Address || !equalJSON(a.Roles, map[string]any{"@type": "User"}) {
			return fail(errors.New("owned mailbox type, name, domain, or role changed; manual review required"))
		}
		if !validPermissions(a.Permissions) {
			return fail(errors.New("owned mailbox permissions are malformed or unsupported"))
		}
		if entry.Transition != "" {
			// Recover a crash between a permission update and its state commit.
			switch {
			case equalJSON(a.Permissions, SuspendedPermissions):
				entry.Status = "suspended"
			case len(entry.PreviousPermissions) > 0 && equalJSON(a.Permissions, entry.PreviousPermissions):
				entry.Status = "active"
				entry.PreviousPermissions = nil
			default:
				return fail(errors.New("uncertain permission transition conflicts with destination"))
			}
			entry.Transition = ""
		}
		if entry.Status == "suspended" && (!equalJSON(a.Permissions, SuspendedPermissions) || len(entry.PreviousPermissions) == 0) {
			return fail(errors.New("suspended mailbox permissions drifted; refusing to overwrite or reactivate"))
		}
		if owner := usedAddresses[entry.Address]; owner != "" && owner != a.ID {
			return fail(errors.New("owned address collides with another mailbox or alias"))
		}
		usedAddresses[entry.Address] = a.ID
	}
	ids := make([]string, 0, len(users))
	for id := range users {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		u := users[id]
		entry := plan.Next.Entries[id]
		if entry == nil {
			addr, err := address(u, p.Domain, p.AddressOverrides)
			if err != nil {
				return fail(fmt.Errorf("identity %s: %w", id, err))
			}
			if usedAddresses[addr] != "" {
				return fail(fmt.Errorf("identity %s: address collision; an explicit override or reviewed ownership migration is required", id))
			}
			usedAddresses[addr] = "new:" + id
			permissions := json.RawMessage(`{"@type":"Inherit"}`)
			if !u.Active {
				permissions = SuspendedPermissions
			}
			object := map[string]any{
				"@type": "User", "name": strings.SplitN(addr, "@", 2)[0], "domainId": p.DomainID,
				"description": displayName(u), "credentials": map[string]any{}, "memberGroupIds": map[string]bool{},
				"roles": map[string]any{"@type": "User"}, "permissions": permissions,
				"quotas": map[string]int64{"maxDiskQuota": p.QuotaBytes}, "aliases": map[string]any{},
				"encryptionAtRest": map[string]any{"@type": "Disabled"},
			}
			plan.Actions = append(plan.Actions, Action{Kind: "create", IdentityID: id, Address: addr, Patch: object})
			continue
		}
		entry.MissingSince = nil
		a := accounts[entry.AccountID]
		patch := map[string]any{}
		kind := "update"
		if a.Description != displayName(u) {
			patch["description"] = displayName(u)
		}
		if a.Quotas["maxDiskQuota"] != p.QuotaBytes {
			// Patch only our owned quota; leave unrelated limits unchanged.
			patch["quotas/maxDiskQuota"] = p.QuotaBytes
		}
		if !u.Active && entry.Status != "suspended" {
			patch["permissions"], kind = SuspendedPermissions, "suspend"
		} else if u.Active && entry.Status == "suspended" {
			patch["permissions"], kind = entry.PreviousPermissions, "resume"
		}
		if len(patch) > 0 {
			plan.Actions = append(plan.Actions, Action{Kind: kind, IdentityID: id, Address: entry.Address, Patch: patch, Current: a})
		}
	}
	for id, entry := range plan.Next.Entries {
		if _, ok := users[id]; ok {
			continue
		}
		if entry.MissingSince == nil {
			t := now
			entry.MissingSince = &t
		}
		if entry.Status != "suspended" && now.Sub(*entry.MissingSince) >= p.MissingGrace {
			plan.Actions = append(plan.Actions, Action{Kind: "suspend", IdentityID: id, Address: entry.Address,
				Reason: "absent beyond grace period", Patch: map[string]any{"permissions": SuspendedPermissions}, Current: accounts[entry.AccountID]})
		}
	}
	suspensions := 0
	for _, action := range plan.Actions {
		if action.Kind == "suspend" {
			suspensions++
		}
	}
	if suspensions > p.MaxSuspensions || len(previous.Entries) > 0 && float64(suspensions)/float64(len(previous.Entries)) > p.MaxSuspendFraction {
		return fail(errors.New("suspension safety threshold exceeded; no mutations performed"))
	}
	sort.Slice(plan.Actions, func(i, j int) bool { return plan.Actions[i].IdentityID < plan.Actions[j].IdentityID })
	return plan, nil
}

func displayName(u identity.User) string {
	if s := strings.TrimSpace(u.DisplayName); s != "" {
		return s
	}
	return strings.TrimSpace(u.GivenName + " " + u.FamilyName)
}

func validPermissions(raw json.RawMessage) bool {
	var p struct {
		Type string `json:"@type"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return false
	}
	return p.Type == "Inherit" || p.Type == "Merge" || p.Type == "Replace"
}

func (e *Engine) Run(ctx context.Context, apply bool) (Plan, error) {
	s, err := e.Source.Snapshot(ctx)
	if err != nil {
		return Plan{}, err
	}
	if err := s.Validate(e.Policy.Issuer, e.Policy.Scope, e.Policy.MaxUsers); err != nil {
		return Plan{}, err
	}
	d, err := e.Target.Snapshot(ctx)
	if err != nil {
		return Plan{}, err
	}
	previous, err := e.Store.Load()
	if err != nil {
		return Plan{}, err
	}
	now := time.Now().UTC()
	if e.Now != nil {
		now = e.Now().UTC()
	}
	plan, err := e.Build(s, d, previous, now)
	if err != nil || !apply {
		return plan, err
	}
	// Commit observation/grace timers and recovered transitions only after both
	// snapshots and the entire plan passed validation. Dry runs never save state.
	if err := e.Store.Save(plan.Next); err != nil {
		return plan, err
	}
	for _, action := range plan.Actions {
		if err := ctx.Err(); err != nil {
			return plan, err
		}
		entry := plan.Next.Entries[action.IdentityID]
		if action.Kind == "create" {
			entry = &state.Entry{Address: action.Address, Status: "pending"}
			plan.Next.Entries[action.IdentityID] = entry
			if err := e.Store.Save(plan.Next); err != nil {
				return plan, err
			}
			id, err := e.Target.Create(ctx, action.Patch)
			if err != nil {
				var rejected *mailbox.RejectedError
				if errors.As(err, &rejected) {
					// The server explicitly confirmed no creation. It is safe to
					// release the intent and retry after configuration is fixed.
					delete(plan.Next.Entries, action.IdentityID)
					if saveErr := e.Store.Save(plan.Next); saveErr != nil {
						return plan, saveErr
					}
					return plan, err
				}
				return plan, fmt.Errorf("create outcome uncertain; inspect pending state before retrying: %w", err)
			}
			plan.Applied++
			entry.AccountID, entry.Status = id, "active"
			if equalJSON(action.Patch["permissions"], SuspendedPermissions) {
				entry.Status = "suspended"
				entry.PreviousPermissions = json.RawMessage(`{"@type":"Inherit"}`)
			}
		} else {
			if action.Kind == "suspend" {
				entry.PreviousPermissions = append(json.RawMessage{}, action.Current.Permissions...)
				entry.Transition = "suspend"
			} else if action.Kind == "resume" {
				entry.Transition = "resume"
			}
			if err := e.Store.Save(plan.Next); err != nil {
				return plan, err
			}
			if err := e.Target.Update(ctx, action.Current, action.Patch); err != nil {
				return plan, err
			}
			plan.Applied++
			switch action.Kind {
			case "suspend":
				entry.Status = "suspended"
			case "resume":
				entry.Status, entry.PreviousPermissions = "active", nil
			}
			entry.Transition = ""
		}
		if err := e.Store.Save(plan.Next); err != nil {
			return plan, err
		}
	}
	plan.Next.LastComplete = now
	if err := e.Store.Save(plan.Next); err != nil {
		return plan, err
	}
	return plan, nil
}
