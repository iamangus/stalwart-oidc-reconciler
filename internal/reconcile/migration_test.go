package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/identity"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/state"
)

func migrationFixture(t *testing.T) (*Engine, *fakeSource, *fakeTarget, *memoryStore, Migration) {
	t.Helper()
	e, src, target, store := fixture()
	run(t, e, true)
	former := target.accounts[0]
	former.ID, former.Name = "2", "former"
	target.accounts = append(target.accounts, former)
	store.data.Entries["former-id"] = &state.Entry{AccountID: "2", Address: "former@example.com", Status: "active"}
	old := e.Policy.Fingerprint()
	e.Policy.SourceKind, e.Policy.Issuer, e.Policy.Scope = "keycloak", "https://id.example.com/realms/apps", "apps"
	e.Policy.IncludeIDs = []string{"new-alice"}
	src.snapshot.Issuer, src.snapshot.Scope, src.snapshot.Users[0].ID = e.Policy.Issuer, e.Policy.Scope, "new-alice"
	target.writes = 0
	return e, src, target, store, Migration{FromFingerprint: old, ToFingerprint: e.Policy.Fingerprint(),
		Mappings: []OwnershipMapping{{FromID: "alice", ToID: "new-alice", AccountID: "1", Address: "alice.example@example.com", Status: "active"}},
		Protect:  []ProtectedMapping{{IdentityID: "former-id", AccountID: "2", Address: "former@example.com", Status: "active"}}}
}

func TestReviewedMigration(t *testing.T) {
	e, src, target, store, spec := migrationFixture(t)
	before := clone(store.data)
	saves := store.saves
	plan, err := e.Migrate(context.Background(), spec, false)
	if err != nil || len(plan.Actions) != 0 || target.writes != 0 || store.saves != saves || !equalJSON(before, store.data) {
		t.Fatalf("dry run mutated or failed: %v", err)
	}
	if !plan.Next.Entries["former-id"].Protected || before.Entries["former-id"].Protected {
		t.Fatal("protection lost or input mutated")
	}
	if _, err = e.Migrate(context.Background(), spec, true); err != nil {
		t.Fatal(err)
	}
	if store.data.Entries["new-alice"].AccountID != "1" || store.data.Entries["alice"] != nil || target.writes != 0 {
		t.Fatal("ownership mapping mutated mailbox")
	}
	if _, err = e.Migrate(context.Background(), spec, true); err != nil {
		t.Fatal("repeat failed", err)
	}
	e.Now = func() time.Time { return time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) }
	src.snapshot.Users = append(src.snapshot.Users, identity.User{ID: "unapproved", GivenName: "Other", FamilyName: "Person", Human: true, Active: true})
	plan = run(t, e, true)
	if len(plan.Actions) != 0 || store.data.Entries["former-id"].MissingSince != nil || target.writes != 0 {
		t.Fatal("protected or unapproved identity managed")
	}
	src.snapshot.Users[0].Active = false
	plan = run(t, e, true)
	if len(plan.Actions) != 1 || plan.Actions[0].IdentityID != "new-alice" || store.data.Entries["former-id"].Status != "active" {
		t.Fatal("suspension escaped pilot scope")
	}
}

func TestMigrationRejectsUnsafeDispositions(t *testing.T) {
	for _, mode := range []string{"source fingerprint", "target fingerprint", "account", "address", "status", "unknown user", "omitted", "duplicate", "transition", "mailbox drift", "directory failure", "save failure", "would mutate"} {
		t.Run(mode, func(t *testing.T) {
			e, src, target, store, spec := migrationFixture(t)
			switch mode {
			case "source fingerprint":
				spec.FromFingerprint = "wrong"
			case "target fingerprint":
				spec.ToFingerprint = "wrong"
			case "account":
				spec.Mappings[0].AccountID = "other"
			case "address":
				spec.Mappings[0].Address = "other@example.com"
			case "status":
				spec.Mappings[0].Status = "suspended"
			case "unknown user":
				spec.Mappings[0].ToID = "unknown"
			case "omitted":
				spec.Protect = nil
			case "duplicate":
				spec.Protect[0].IdentityID = "alice"
			case "transition":
				store.data.Entries["alice"].Transition = "suspend"
			case "mailbox drift":
				target.accounts[0].Name = "different"
			case "directory failure":
				src.err = errors.New("offline")
			case "save failure":
				store.failAt = store.saves + 1
			case "would mutate":
				src.snapshot.Users[0].DisplayName = "Changed Name"
			}
			before, _ := json.Marshal(store.data)
			if _, err := e.Migrate(context.Background(), spec, true); err == nil {
				t.Fatal("unsafe migration accepted")
			}
			after, _ := json.Marshal(store.data)
			if string(before) != string(after) || target.writes != 0 {
				t.Fatal("failed migration changed ownership or mailbox")
			}
		})
	}
}
