package reconcile

import (
	"context"
	"errors"
	"testing"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/identity"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/mailbox"
)

type fakePublisher struct {
	store  *memoryStore
	source *fakeSource
	calls  int
	err    error
}

func (p *fakePublisher) PublishAddress(_ context.Context, id, address string) error {
	p.calls++
	entry := p.store.data.Entries[id]
	if entry == nil || entry.Status != "active" || entry.AccountID == "" || entry.Address != address {
		return errors.New("published before durable creation")
	}
	if p.err != nil {
		return p.err
	}
	for i := range p.source.snapshot.Users {
		if p.source.snapshot.Users[i].ID == id {
			p.source.snapshot.Users[i].MailAddress = address
		}
	}
	return nil
}

func TestSignupProvisionPublishAndRetry(t *testing.T) {
	e, src, target, store := fixture()
	e.Policy.IncludeIDs, e.Policy.OrganizationID = []string{"pilot"}, "signup-org"
	src.snapshot.Users[0].OrganizationMember = true
	publisher := &fakePublisher{store: store, source: src, err: errors.New("provider unavailable")}
	e.Publisher = publisher
	plan := run(t, e, false)
	if len(plan.Actions) != 2 || target.writes != 0 || publisher.calls != 0 {
		t.Fatal("dry-run mutated or omitted publication")
	}
	if _, err := e.Run(context.Background(), true); err == nil {
		t.Fatal("publication failure hidden")
	}
	if target.writes != 1 || store.data.Entries["alice"].AccountID != "1" {
		t.Fatal("confirmed mailbox ownership lost")
	}
	publisher.err = nil
	plan = run(t, e, true)
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != "publish_address" || target.writes != 1 {
		t.Fatal("retry recreated/changed mailbox")
	}
	if len(run(t, e, true).Actions) != 0 {
		t.Fatal("not idempotent")
	}
	src.snapshot.Users[0].GivenName = "Changed"
	if len(run(t, e, true).Actions) != 0 || store.data.Entries["alice"].Address != "alice.example@example.com" {
		t.Fatal("profile change renamed address")
	}
}

func TestSignupEligibilityAndClaimsFailClosed(t *testing.T) {
	for _, mode := range []string{"not member", "unfinished", "disabled", "preclaimed", "uncertain create", "drift"} {
		t.Run(mode, func(t *testing.T) {
			e, src, target, store := fixture()
			e.Policy.IncludeIDs, e.Policy.OrganizationID, e.Policy.AllowEmpty = []string{"pilot"}, "org", true
			src.snapshot.Users[0].OrganizationMember = true
			publisher := &fakePublisher{store: store, source: src}
			e.Publisher = publisher
			switch mode {
			case "not member":
				src.snapshot.Users[0].OrganizationMember = false
			case "unfinished":
				src.snapshot.Users[0].OnboardingPending = true
			case "disabled":
				src.snapshot.Users[0].Active = false
			case "preclaimed":
				src.snapshot.Users[0].MailAddress = "somebody@example.com"
			case "uncertain create":
				target.uncertain = true
			case "drift":
				run(t, e, true)
				target.writes = 0
				publisher.calls = 0
				src.snapshot.Users[0].MailAddress = "different@example.com"
			}
			_, err := e.Run(context.Background(), true)
			if mode == "preclaimed" || mode == "uncertain create" || mode == "drift" {
				if err == nil {
					t.Fatal("unsafe state accepted")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if publisher.calls != 0 {
				t.Fatal("published unconfirmed/conflicting address")
			}
			if mode != "uncertain create" && target.writes != 0 {
				t.Fatal("ineligible or conflicted mailbox mutated")
			}
		})
	}
}

func TestNumericSuffixesReserveAccountsAliasesAndState(t *testing.T) {
	e, src, target, store := fixture()
	e.Policy.NumericSuffixes = true
	run(t, e, true)
	src.snapshot.Users = append(src.snapshot.Users,
		identity.User{ID: "bob", GivenName: "Alice", FamilyName: "Example", Human: true, Active: true},
		identity.User{ID: "carol", GivenName: "Alice", FamilyName: "Example", Human: true, Active: true})
	plan := run(t, e, true)
	if len(plan.Actions) != 2 || store.data.Entries["bob"].Address != "alice.example2@example.com" || store.data.Entries["carol"].Address != "alice.example3@example.com" {
		t.Fatal(plan)
	}
	store.data.Entries["bob"].Protected = true
	src.snapshot.Users = append(src.snapshot.Users[:1], src.snapshot.Users[2])
	src.snapshot.Users = append(src.snapshot.Users, identity.User{ID: "dave", GivenName: "Alice", FamilyName: "Example", Human: true, Active: true})
	run(t, e, true)
	if store.data.Entries["dave"].Address != "alice.example4@example.com" || target.writes != 4 {
		t.Fatal("recycled protected address")
	}
	// Explicit administrative overrides are exact, never silently suffixed.
	src.snapshot.Users = append(src.snapshot.Users, identity.User{ID: "eve", GivenName: "Other", FamilyName: "Name", Human: true, Active: true})
	e.Policy.AddressOverrides = map[string]string{"eve": "alice.example"}
	if _, err := e.Run(context.Background(), true); err == nil {
		t.Fatal("suffixed explicit override")
	}
}

func TestNumericSuffixSkipsDisabledAliasesAndForeignClaims(t *testing.T) {
	e, src, target, store := fixture()
	e.Policy.NumericSuffixes = true
	run(t, e, true)
	target.accounts[0].Aliases = map[string]mailbox.Alias{"reserved": {Name: "alice.example2", DomainID: e.Policy.DomainID, Enabled: false}}
	src.snapshot.Users = append(src.snapshot.Users,
		identity.User{ID: "bob", GivenName: "Alice", FamilyName: "Example", Human: true, Active: true},
		identity.User{ID: "foreign", MailAddress: "alice.example3@example.com", Human: true, Active: true})
	e.Policy.ExcludeIDs = []string{"foreign"}
	run(t, e, true)
	if store.data.Entries["bob"].Address != "alice.example4@example.com" {
		t.Fatal("reused alias or published foreign claim")
	}
}
