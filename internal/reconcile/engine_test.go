package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/identity"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/mailbox"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/state"
)

type memoryStore struct {
	data          state.Data
	saves, failAt int
}

func (m *memoryStore) Load() (state.Data, error) { return clone(m.data), nil }
func (m *memoryStore) Save(d state.Data) error {
	m.saves++
	if m.saves == m.failAt {
		return errors.New("disk full")
	}
	m.data = clone(d)
	return nil
}

type fakeSource struct {
	snapshot identity.Snapshot
	err      error
}

func (f *fakeSource) Snapshot(context.Context) (identity.Snapshot, error) { return f.snapshot, f.err }

type fakeTarget struct {
	accounts      []mailbox.Account
	writes, reads int
	uncertain     bool
	reject        bool
}

func (f *fakeTarget) Snapshot(context.Context) (mailbox.Snapshot, error) {
	f.reads++
	b, _ := json.Marshal(f.accounts)
	var a []mailbox.Account
	_ = json.Unmarshal(b, &a)
	return mailbox.Snapshot{Accounts: a}, nil
}
func (f *fakeTarget) Create(_ context.Context, object map[string]any) (string, error) {
	f.writes++
	if f.reject {
		return "", &mailbox.RejectedError{Code: "forbidden"}
	}
	b, _ := json.Marshal(object)
	var a mailbox.Account
	_ = json.Unmarshal(b, &a)
	a.ID = fmt.Sprint(len(f.accounts) + 1)
	f.accounts = append(f.accounts, a)
	if f.uncertain {
		return "", errors.New("response lost")
	}
	return a.ID, nil
}
func (f *fakeTarget) Update(_ context.Context, expected mailbox.Account, patch map[string]any) error {
	f.writes++
	for i := range f.accounts {
		a := &f.accounts[i]
		if a.ID != expected.ID {
			continue
		}
		if !equalJSON(a, expected) {
			return errors.New("changed")
		}
		if v, ok := patch["description"]; ok {
			a.Description = v.(string)
		}
		if v, ok := patch["quotas/maxDiskQuota"]; ok {
			if a.Quotas == nil {
				a.Quotas = map[string]int64{}
			}
			a.Quotas["maxDiskQuota"] = v.(int64)
		}
		if v, ok := patch["permissions"]; ok {
			a.Permissions, _ = json.Marshal(v)
		}
		return nil
	}
	return errors.New("missing")
}

func fixture() (*Engine, *fakeSource, *fakeTarget, *memoryStore) {
	src := &fakeSource{snapshot: identity.Snapshot{Complete: true, Issuer: "https://id.example.com", Scope: "org1", Users: []identity.User{
		{ID: "alice", GivenName: "Alice", FamilyName: "Example", DisplayName: "Alice Example", Human: true, Active: true},
	}}}
	target := &fakeTarget{}
	store := &memoryStore{data: state.Data{Version: 1, Entries: map[string]*state.Entry{}}}
	e := &Engine{Source: src, Target: target, Store: store, Now: func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }, Policy: Policy{
		Issuer: src.snapshot.Issuer, Scope: "org1", SourceKind: "file", Destination: "https://mail.example.com/jmap",
		Domain: "example.com", DomainID: "domain1", QuotaBytes: 1024, MaxUsers: 100,
		MissingGrace: 24 * time.Hour, MaxSuspensions: 5, MaxSuspendFraction: 1,
	}}
	return e, src, target, store
}

func run(t *testing.T, e *Engine, apply bool) Plan {
	t.Helper()
	p, err := e.Run(context.Background(), apply)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCreateIdempotenceAndStableAddress(t *testing.T) {
	e, src, target, store := fixture()
	plan := run(t, e, true)
	if len(plan.Actions) != 1 || store.data.Entries["alice"].Address != "alice.example@example.com" {
		t.Fatal(plan)
	}
	if len(run(t, e, true).Actions) != 0 || target.writes != 1 {
		t.Fatal("not idempotent")
	}
	src.snapshot.Users[0].GivenName, src.snapshot.Users[0].DisplayName = "Alicia", "Alicia Example"
	plan = run(t, e, true)
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != "update" || target.accounts[0].Name != "alice.example" {
		t.Fatal("name change renamed mailbox")
	}
	if target.accounts[0].Description != "Alicia Example" {
		t.Fatal("profile not updated")
	}
}

func TestDryRunNeverWritesOrAdvancesMissingTimer(t *testing.T) {
	e, src, target, store := fixture()
	if len(run(t, e, false).Actions) != 1 || store.saves != 0 || target.writes != 0 {
		t.Fatal("dry run wrote")
	}
	run(t, e, true)
	src.snapshot.Users = nil
	e.Policy.AllowEmpty = true
	before := store.saves
	run(t, e, false)
	if store.data.Entries["alice"].MissingSince != nil || store.saves != before {
		t.Fatal("dry run advanced timer")
	}
}

func TestSnapshotsFailClosed(t *testing.T) {
	for _, kind := range []string{"source error", "incomplete", "wrong issuer", "wrong org", "duplicate", "empty", "over limit"} {
		t.Run(kind, func(t *testing.T) {
			e, src, target, store := fixture()
			switch kind {
			case "source error":
				src.err = errors.New("unavailable")
			case "incomplete":
				src.snapshot.Complete = false
			case "wrong issuer":
				src.snapshot.Issuer = "https://other.example.com"
			case "wrong org":
				src.snapshot.Scope = "other"
			case "duplicate":
				src.snapshot.Users = append(src.snapshot.Users, src.snapshot.Users[0])
			case "empty":
				src.snapshot.Users = nil
			case "over limit":
				e.Policy.MaxUsers = 0
			}
			if _, err := e.Run(context.Background(), true); err == nil {
				t.Fatal("accepted unsafe snapshot")
			}
			if target.writes != 0 || store.saves != 0 {
				t.Fatal("mutations on bad snapshot")
			}
		})
	}
}

func TestCollisionNeverAdoptsAndNeverPartiallyApplies(t *testing.T) {
	for _, kind := range []string{"unmanaged account", "alias", "duplicate names"} {
		t.Run(kind, func(t *testing.T) {
			e, src, target, store := fixture()
			switch kind {
			case "unmanaged account":
				target.accounts = []mailbox.Account{{ID: "unmanaged", Name: "alice.example", DomainID: "domain1", Type: "User"}}
			case "alias":
				target.accounts = []mailbox.Account{{ID: "other", Name: "else", DomainID: "other-domain", Type: "Group", Aliases: map[string]mailbox.Alias{"a": {Name: "alice.example", DomainID: "domain1"}}}}
			case "duplicate names":
				other := src.snapshot.Users[0]
				other.ID = "another"
				src.snapshot.Users = append(src.snapshot.Users, other)
			}
			if _, err := e.Run(context.Background(), true); err == nil {
				t.Fatal("collision accepted")
			}
			if target.writes != 0 || store.saves != 0 {
				t.Fatal("partial application")
			}
		})
	}
}

func TestSuspendResumeRetainsMailAndPermissions(t *testing.T) {
	e, src, target, store := fixture()
	run(t, e, true)
	original := json.RawMessage(`{"@type":"Merge","enabledPermissions":{"emailReceive":true},"disabledPermissions":{"imapAuthenticate":true}}`)
	target.accounts[0].Permissions = original
	src.snapshot.Users[0].Active = false
	if p := run(t, e, true); len(p.Actions) != 1 || p.Actions[0].Kind != "suspend" {
		t.Fatal(p)
	}
	if store.data.Entries["alice"].Status != "suspended" || !equalJSON(target.accounts[0].Permissions, SuspendedPermissions) {
		t.Fatal("not suspended")
	}
	if !equalJSON(store.data.Entries["alice"].PreviousPermissions, original) {
		t.Fatal("permissions lost")
	}
	if len(run(t, e, true).Actions) != 0 {
		t.Fatal("suspension not idempotent")
	}
	src.snapshot.Users[0].Active = true
	if p := run(t, e, true); p.Actions[0].Kind != "resume" {
		t.Fatal(p)
	}
	if !equalJSON(target.accounts[0].Permissions, original) || store.data.Entries["alice"].Status != "active" {
		t.Fatal("resume did not restore permissions")
	}
}

func TestMissingGraceAndBulkCircuitBreaker(t *testing.T) {
	e, src, target, store := fixture()
	run(t, e, true)
	src.snapshot.Users = nil
	e.Policy.AllowEmpty = true
	if len(run(t, e, true).Actions) != 0 || store.data.Entries["alice"].MissingSince == nil {
		t.Fatal("missing grace not started")
	}
	start := e.Now()
	e.Now = func() time.Time { return start.Add(25 * time.Hour) }
	e.Policy.MaxSuspendFraction = 0.5
	before := target.writes
	if _, err := e.Run(context.Background(), true); err == nil {
		t.Fatal("mass suspension accepted")
	}
	if target.writes != before {
		t.Fatal("mass suspension partially applied")
	}
	e.Policy.MaxSuspendFraction = 1
	p := run(t, e, true)
	if len(p.Actions) != 1 || p.Actions[0].Kind != "suspend" || len(target.accounts) != 1 {
		t.Fatal("mail deleted or not suspended")
	}
}

func TestUncertainCreateNeverAdoptsOnRetry(t *testing.T) {
	e, _, target, store := fixture()
	target.uncertain = true
	if _, err := e.Run(context.Background(), true); err == nil {
		t.Fatal("expected uncertain create")
	}
	if store.data.Entries["alice"].Status != "pending" || len(target.accounts) != 1 {
		t.Fatal("creation intent not durable")
	}
	target.uncertain = false
	if _, err := e.Run(context.Background(), true); err == nil {
		t.Fatal("uncertain account adopted")
	}
	if target.writes != 1 {
		t.Fatal("retried uncertain mutation")
	}
}

func TestExplicitRejectionDoesNotLeaveUncertainCreationIntent(t *testing.T) {
	e, _, target, store := fixture()
	target.reject = true
	if _, err := e.Run(context.Background(), true); err == nil {
		t.Fatal("rejection not surfaced")
	}
	if len(store.data.Entries) != 0 || len(target.accounts) != 0 {
		t.Fatal("known rejection retained uncertain creation intent")
	}
	target.reject = false
	run(t, e, true)
	if len(target.accounts) != 1 || store.data.Entries["alice"].Status != "active" {
		t.Fatal("safe retry did not create account")
	}
}

func TestCrashRecoveryPermissionTransitions(t *testing.T) {
	e, src, target, store := fixture()
	run(t, e, true)
	src.snapshot.Users[0].Active = false
	store.saves = 0
	store.failAt = 3 // fail state commit AFTER successful remote suspension
	if _, err := e.Run(context.Background(), true); err == nil {
		t.Fatal("disk failure not surfaced")
	}
	if store.data.Entries["alice"].Transition != "suspend" {
		t.Fatal("missing write-ahead transition")
	}
	store.failAt = 0
	run(t, e, true)
	if store.data.Entries["alice"].Status != "suspended" {
		t.Fatal("failed to recover suspension")
	}
	src.snapshot.Users[0].Active = true
	store.saves = 0
	store.failAt = 3
	if _, err := e.Run(context.Background(), true); err == nil {
		t.Fatal("expected commit failure")
	}
	store.failAt = 0
	run(t, e, true)
	if store.data.Entries["alice"].Status != "active" || !equalJSON(target.accounts[0].Permissions, map[string]any{"@type": "Inherit"}) {
		t.Fatal("failed resume recovery")
	}
}

func TestOwnershipDriftAndScopeChangesBlocked(t *testing.T) {
	for _, kind := range []string{"role", "address", "missing account", "permissions", "scope"} {
		t.Run(kind, func(t *testing.T) {
			e, src, target, store := fixture()
			run(t, e, true)
			switch kind {
			case "role":
				target.accounts[0].Roles = json.RawMessage(`{"@type":"Admin"}`)
			case "address":
				target.accounts[0].Name = "renamed"
			case "missing account":
				target.accounts = nil
			case "permissions":
				src.snapshot.Users[0].Active = false
				run(t, e, true)
				target.accounts[0].Permissions = json.RawMessage(`{"@type":"Inherit"}`)
				src.snapshot.Users[0].Active = true
			case "scope":
				e.Policy.Destination = "https://other.example.com/jmap"
			}
			before := target.writes
			saves := store.saves
			if _, err := e.Run(context.Background(), true); err == nil {
				t.Fatal("unsafe drift accepted")
			}
			if before != target.writes || saves != store.saves {
				t.Fatal("mutated on ownership drift")
			}
		})
	}
}

func TestExcludeMachinesAndOverrideNames(t *testing.T) {
	e, src, target, store := fixture()
	src.snapshot.Users = append(src.snapshot.Users, identity.User{ID: "bot", Active: true}, identity.User{ID: "break-glass", Human: true, Active: true})
	e.Policy.ExcludeIDs = []string{"break-glass"}
	src.snapshot.Users[0].GivenName = "李"
	e.Policy.AddressOverrides = map[string]string{"alice": "alice.example"}
	plan := run(t, e, true)
	if plan.Users != 1 || len(target.accounts) != 1 || len(store.data.Entries) != 1 {
		t.Fatal("machine/excluded user provisioned")
	}
}

func TestAddressNormalization(t *testing.T) {
	for _, test := range []struct{ first, last, want string }{
		{"Élodie", "O’Connor", "elodie.oconnor@example.com"},
		{" Mary Jane ", "Smith-Jones", "mary-jane.smith-jones@example.com"},
	} {
		got, err := address(identity.User{GivenName: test.first, FamilyName: test.last}, "example.com", nil)
		if err != nil || got != test.want {
			t.Fatalf("%q %v", got, err)
		}
	}
	for _, first := range []string{"", "李", "alice@example.com", strings.Repeat("a", 64)} {
		if _, err := address(identity.User{GivenName: first, FamilyName: "Test"}, "example.com", nil); err == nil {
			t.Fatalf("accepted %q", first)
		}
	}
}
