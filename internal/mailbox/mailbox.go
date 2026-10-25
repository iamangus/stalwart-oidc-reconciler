package mailbox

import (
	"context"
	"encoding/json"
	"fmt"
)

// RejectedError means a successful API response explicitly confirmed that the
// single creation was not performed. Transport/malformed-response errors must
// NOT use this type: their outcome is uncertain.
type RejectedError struct {
	Code       string
	Properties []string
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("Stalwart rejected account creation (type=%q, properties=%q)", e.Code, e.Properties)
}

type Alias struct {
	Name     string `json:"name"`
	DomainID string `json:"domainId"`
	Enabled  bool   `json:"enabled"`
}

// Account excludes credentials on purpose. The reconciler never reads secrets.
type Account struct {
	ID          string           `json:"id"`
	Type        string           `json:"@type"`
	Name        string           `json:"name"`
	DomainID    string           `json:"domainId"`
	Description string           `json:"description"`
	Roles       json.RawMessage  `json:"roles"`
	Permissions json.RawMessage  `json:"permissions"`
	Quotas      map[string]int64 `json:"quotas"`
	Aliases     map[string]Alias `json:"aliases"`
}

type Snapshot struct {
	Accounts []Account
}

type Destination interface {
	Snapshot(context.Context) (Snapshot, error)
	Create(context.Context, map[string]any) (id string, err error)
	Update(context.Context, Account, map[string]any) error
}
