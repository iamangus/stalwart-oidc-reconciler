// Package identity defines the provider-independent provisioning contract.
// OIDC itself cannot enumerate users; adapters must provide complete snapshots.
package identity

import (
	"context"
	"errors"
	"fmt"
)

type User struct {
	ID                 string `json:"id"`
	GivenName          string `json:"given_name"`
	FamilyName         string `json:"family_name"`
	DisplayName        string `json:"display_name"`
	Human              bool   `json:"human"`
	Active             bool   `json:"active"`
	MailAddress        string `json:"mail_address,omitempty"`
	OrganizationMember bool   `json:"organization_member,omitempty"`
	OnboardingPending  bool   `json:"onboarding_pending,omitempty"`
}

type Snapshot struct {
	Complete bool   `json:"complete"`
	Issuer   string `json:"issuer"`
	Scope    string `json:"scope"`
	Revision string `json:"revision"`
	Users    []User `json:"users"`
}

type Source interface {
	Snapshot(context.Context) (Snapshot, error)
}

// AddressPublisher can publish only an already-owned mailbox address. It must
// reject a conflicting existing claim rather than overwrite or adopt it.
type AddressPublisher interface {
	PublishAddress(context.Context, string, string) error
}

func (s Snapshot) Validate(issuer, scope string, maxUsers int) error {
	if !s.Complete {
		return errors.New("identity snapshot is incomplete")
	}
	if s.Issuer != issuer || s.Scope != scope {
		return errors.New("identity snapshot issuer/scope mismatch")
	}
	if len(s.Users) > maxUsers {
		return errors.New("identity snapshot exceeds configured maximum")
	}
	seen := make(map[string]bool, len(s.Users))
	for _, u := range s.Users {
		if u.ID == "" || seen[u.ID] {
			return fmt.Errorf("identity snapshot contains empty or duplicate ID")
		}
		seen[u.ID] = true
	}
	return nil
}
