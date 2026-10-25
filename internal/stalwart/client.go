// Package stalwart implements the Stalwart 0.16 Community registry/JMAP API.
// It does not use Enterprise-only externalId or SCIM fields.
package stalwart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/httpapi"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/mailbox"
)

type Client struct {
	API         *httpapi.Client
	JMAPPath    string
	MaxAccounts int
	Domain      string
	DomainID    string
}

type envelope struct {
	Responses [][]json.RawMessage `json:"methodResponses"`
}

func (c *Client) call(ctx context.Context, method string, args, out any) error {
	var result envelope
	body := map[string]any{
		"using":       []string{"urn:ietf:params:jmap:core", "urn:stalwart:jmap"},
		"methodCalls": []any{[]any{method, args, "r1"}},
	}
	if err := c.API.Call(ctx, c.JMAPPath, body, &result); err != nil {
		return fmt.Errorf("Stalwart %s: %w", method, err)
	}
	if len(result.Responses) != 1 || len(result.Responses[0]) != 3 {
		return errors.New("Stalwart returned an invalid JMAP envelope")
	}
	var name, id string
	if json.Unmarshal(result.Responses[0][0], &name) != nil || json.Unmarshal(result.Responses[0][2], &id) != nil || id != "r1" {
		return errors.New("Stalwart returned an invalid JMAP response tag")
	}
	if name != method {
		// Descriptions can contain input data or secrets; intentionally omit them.
		return fmt.Errorf("Stalwart rejected JMAP method %s", method)
	}
	if err := json.Unmarshal(result.Responses[0][1], out); err != nil {
		return errors.New("Stalwart returned an invalid JMAP result")
	}
	return nil
}

var properties = []string{"id", "@type", "name", "domainId", "description", "roles", "permissions", "quotas", "aliases"}

func (c *Client) get(ctx context.Context, ids []string) ([]mailbox.Account, error) {
	var r struct {
		List     []mailbox.Account `json:"list"`
		NotFound []string          `json:"notFound"`
	}
	if err := c.call(ctx, "x:Account/get", map[string]any{"ids": ids, "properties": properties}, &r); err != nil {
		return nil, err
	}
	if len(r.NotFound) != 0 || len(r.List) != len(ids) {
		return nil, errors.New("Stalwart accounts changed or account read was incomplete")
	}
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}
	for _, a := range r.List {
		if !wanted[a.ID] || a.Name == "" || a.DomainID == "" || a.Type == "" {
			return nil, errors.New("Stalwart returned duplicate or malformed account")
		}
		delete(wanted, a.ID)
	}
	return r.List, nil
}

func (c *Client) Snapshot(ctx context.Context) (mailbox.Snapshot, error) {
	var s mailbox.Snapshot
	if c.DomainID != "" {
		var domain struct {
			List []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"list"`
		}
		if err := c.call(ctx, "x:Domain/get", map[string]any{"ids": []string{c.DomainID}, "properties": []string{"id", "name"}}, &domain); err != nil {
			return s, err
		}
		if len(domain.List) != 1 || domain.List[0].ID != c.DomainID || domain.List[0].Name != c.Domain {
			return s, errors.New("Stalwart domain_id does not resolve to the configured mail domain")
		}
	}
	var total *int
	seen := map[string]bool{}
	for offset := 0; ; {
		var r struct {
			IDs      []string `json:"ids"`
			Total    *int     `json:"total"`
			Position int      `json:"position"`
		}
		if err := c.call(ctx, "x:Account/query", map[string]any{
			"filter": map[string]any{}, "position": offset, "limit": 100, "calculateTotal": true,
			"sort": []any{map[string]any{"property": "name", "isAscending": true}},
		}, &r); err != nil {
			return s, err
		}
		if r.Total == nil || *r.Total < 0 || *r.Total > c.MaxAccounts || r.Position != offset {
			return s, errors.New("Stalwart query missing total, invalid position, or exceeds safety bound")
		}
		if total == nil {
			total = r.Total
		} else if *total != *r.Total {
			return s, errors.New("Stalwart account count changed during pagination")
		}
		if len(r.IDs) == 0 && offset < *total {
			return s, errors.New("Stalwart account snapshot is truncated")
		}
		for _, id := range r.IDs {
			if id == "" || seen[id] {
				return s, errors.New("Stalwart account pagination contains duplicate or empty ID")
			}
			seen[id] = true
		}
		if len(r.IDs) > 0 {
			accounts, err := c.get(ctx, r.IDs)
			if err != nil {
				return s, err
			}
			s.Accounts = append(s.Accounts, accounts...)
		}
		offset += len(r.IDs)
		if offset > *total {
			return s, errors.New("Stalwart account pagination exceeds advertised total")
		}
		if offset == *total {
			return s, nil
		}
	}
}

func (c *Client) Create(ctx context.Context, object map[string]any) (string, error) {
	var r struct {
		Created map[string]struct {
			ID string `json:"id"`
		} `json:"created"`
		NotCreated map[string]json.RawMessage `json:"notCreated"`
	}
	if err := c.call(ctx, "x:Account/set", map[string]any{"create": map[string]any{"new": object}}, &r); err != nil {
		return "", err
	}
	if len(r.NotCreated) != 0 && len(r.Created) == 0 {
		var detail struct {
			Type       string   `json:"type"`
			Properties []string `json:"properties"`
		}
		_ = json.Unmarshal(r.NotCreated["new"], &detail)
		return "", &mailbox.RejectedError{Code: detail.Type, Properties: detail.Properties}
	}
	if len(r.Created) != 1 || len(r.NotCreated) != 0 || r.Created["new"].ID == "" {
		return "", errors.New("Stalwart account creation result is ambiguous or missing ID")
	}
	return r.Created["new"].ID, nil
}

// Stalwart 0.16 registry objects do not implement JMAP state/CAS semantics.
// Re-read and compare before patching; callers must enforce one writer for these
// fields. This narrows, but cannot eliminate, the server-side concurrent-write
// window. Do not send a fictitious ifInState and claim atomicity.
func (c *Client) Update(ctx context.Context, expected mailbox.Account, patch map[string]any) error {
	accounts, err := c.get(ctx, []string{expected.ID})
	if err != nil {
		return err
	}
	if !sameJSON(expected, accounts[0]) {
		return errors.New("Stalwart account changed since planning; refusing stale update")
	}
	var r struct {
		Updated    map[string]json.RawMessage `json:"updated"`
		NotUpdated map[string]json.RawMessage `json:"notUpdated"`
	}
	if err := c.call(ctx, "x:Account/set", map[string]any{"update": map[string]any{expected.ID: patch}}, &r); err != nil {
		return err
	}
	if _, ok := r.Updated[expected.ID]; !ok || len(r.NotUpdated) > 0 {
		return errors.New("Stalwart rejected account update")
	}
	return nil
}

func sameJSON(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	var x, y any
	return json.Unmarshal(left, &x) == nil && json.Unmarshal(right, &y) == nil && reflect.DeepEqual(x, y)
}
