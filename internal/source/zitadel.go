package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/httpapi"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/identity"
)

type Zitadel struct {
	API          *httpapi.Client
	Issuer       string
	Organization string
	PageSize     int
	MaxUsers     int
}

type count uint64

func (c *count) UnmarshalJSON(b []byte) error {
	var s string
	if len(b) > 0 && b[0] == '"' {
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
	} else {
		s = string(b)
	}
	n, err := strconv.ParseUint(s, 10, 64)
	*c = count(n)
	return err
}

type zitadelPage struct {
	Details struct {
		Total    count `json:"totalResult"`
		Sequence count `json:"processedSequence"`
	} `json:"details"`
	Result []struct {
		ID      string `json:"userId"`
		State   string `json:"state"`
		Details struct {
			Owner string `json:"resourceOwner"`
		} `json:"details"`
		Human *struct {
			Profile struct {
				Given   string `json:"givenName"`
				Family  string `json:"familyName"`
				Display string `json:"displayName"`
			} `json:"profile"`
		} `json:"human"`
	} `json:"result"`
}

func (z *Zitadel) Snapshot(ctx context.Context) (identity.Snapshot, error) {
	s := identity.Snapshot{Issuer: z.Issuer, Scope: z.Organization}
	if z.PageSize < 1 || z.PageSize > 1000 || z.MaxUsers < 1 {
		return s, errors.New("invalid ZITADEL pagination bounds")
	}
	var total, sequence count
	seen := map[string]bool{}
	for offset := 0; ; {
		var p zitadelPage
		body := map[string]any{
			"query":         map[string]any{"offset": strconv.Itoa(offset), "limit": z.PageSize, "asc": true},
			"sortingColumn": "USER_FIELD_NAME_CREATION_DATE",
			"queries":       []any{map[string]any{"organizationIdQuery": map[string]any{"organizationId": z.Organization}}},
		}
		if err := z.API.Call(ctx, "/v2/users", body, &p); err != nil {
			return s, fmt.Errorf("ZITADEL enumeration: %w", err)
		}
		if offset == 0 {
			total, sequence = p.Details.Total, p.Details.Sequence
			if total > count(z.MaxUsers) {
				return s, errors.New("ZITADEL user count exceeds safety limit")
			}
		} else if total != p.Details.Total || sequence != p.Details.Sequence {
			return s, errors.New("ZITADEL directory changed during pagination; retry next cycle")
		}
		if len(p.Result) == 0 && uint64(offset) < uint64(total) {
			return s, errors.New("ZITADEL returned a truncated snapshot")
		}
		for _, u := range p.Result {
			if u.ID == "" || seen[u.ID] || u.Details.Owner != z.Organization {
				return s, errors.New("ZITADEL returned duplicate ID or wrong organization")
			}
			seen[u.ID] = true
			user := identity.User{ID: u.ID, Human: u.Human != nil}
			switch u.State {
			case "USER_STATE_ACTIVE":
				user.Active = true
			case "USER_STATE_INITIAL", "USER_STATE_INACTIVE", "USER_STATE_LOCKED", "USER_STATE_SUSPEND", "USER_STATE_SUSPENDED", "USER_STATE_DELETED":
			default:
				return s, errors.New("ZITADEL returned an unknown user state")
			}
			if u.Human != nil {
				user.GivenName, user.FamilyName, user.DisplayName = u.Human.Profile.Given, u.Human.Profile.Family, u.Human.Profile.Display
			}
			s.Users = append(s.Users, user)
		}
		offset += len(p.Result)
		if uint64(offset) > uint64(total) || offset > z.MaxUsers {
			return s, errors.New("ZITADEL pagination count mismatch")
		}
		if uint64(offset) == uint64(total) {
			break
		}
	}
	s.Complete = true
	s.Revision = strconv.FormatUint(uint64(sequence), 10)
	return s, nil
}
