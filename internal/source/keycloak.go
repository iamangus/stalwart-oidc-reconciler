package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/httpapi"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/identity"
)

// Keycloak uses a realm-scoped, read-only service account. Every snapshot obtains
// a fresh short-lived token; it never stores or logs tokens or response bodies.
type Keycloak struct {
	HTTP                       *http.Client
	Base, Issuer, Realm        string
	ClientID, ClientSecretFile string
	PageSize, MaxUsers         int
}

func (k *Keycloak) request(ctx context.Context, method, endpoint, token string, form url.Values, result any) error {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return errors.New("construct Keycloak request")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return errors.New("Keycloak transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Keycloak returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, httpapi.MaxBody+1))
	if err != nil || len(b) > httpapi.MaxBody || json.Unmarshal(b, result) != nil {
		return errors.New("Keycloak response malformed or too large")
	}
	return nil
}

type keycloakUser struct {
	ID                   string `json:"id"`
	FirstName            string `json:"firstName"`
	LastName             string `json:"lastName"`
	Enabled              *bool  `json:"enabled"`
	ServiceAccountClient string `json:"serviceAccountClientId"`
}

func (k *Keycloak) read(ctx context.Context, token string) ([]identity.User, error) {
	base := strings.TrimRight(k.Base, "/") + "/admin/realms/" + url.PathEscape(k.Realm) + "/users"
	var count *int
	if err := k.request(ctx, http.MethodGet, base+"/count", token, nil, &count); err != nil {
		return nil, err
	}
	if count == nil {
		return nil, errors.New("Keycloak returned an unknown user count")
	}
	total := *count
	if total < 0 || total > k.MaxUsers {
		return nil, errors.New("Keycloak count exceeds safety limit")
	}
	users := make([]identity.User, 0, total)
	seen := map[string]bool{}
	for offset := 0; offset < total; {
		query := url.Values{"first": {strconv.Itoa(offset)}, "max": {strconv.Itoa(k.PageSize)}, "briefRepresentation": {"false"}}
		var page []keycloakUser
		if err := k.request(ctx, http.MethodGet, base+"?"+query.Encode(), token, nil, &page); err != nil {
			return nil, err
		}
		if len(page) == 0 || len(page) > k.PageSize || offset+len(page) > total {
			return nil, errors.New("Keycloak returned truncated or inconsistent pagination")
		}
		for _, u := range page {
			if u.ID == "" || seen[u.ID] || u.Enabled == nil {
				return nil, errors.New("Keycloak returned empty/duplicate identity or unknown enabled state")
			}
			seen[u.ID] = true
			users = append(users, identity.User{ID: u.ID, GivenName: u.FirstName, FamilyName: u.LastName,
				DisplayName: strings.TrimSpace(u.FirstName + " " + u.LastName), Active: *u.Enabled, Human: u.ServiceAccountClient == ""})
		}
		offset += len(page)
	}
	var after *int
	if err := k.request(ctx, http.MethodGet, base+"/count", token, nil, &after); err != nil {
		return nil, err
	}
	if after == nil || *after != total {
		return nil, errors.New("Keycloak count changed during enumeration")
	}
	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	return users, nil
}

func (k *Keycloak) Snapshot(ctx context.Context) (identity.Snapshot, error) {
	s := identity.Snapshot{Issuer: k.Issuer, Scope: k.Realm}
	if k.HTTP == nil || k.PageSize < 1 || k.PageSize > 1000 || k.MaxUsers < 1 || k.Realm == "" ||
		k.Issuer != strings.TrimRight(k.Base, "/")+"/realms/"+url.PathEscape(k.Realm) {
		return s, errors.New("invalid Keycloak realm, issuer or pagination configuration")
	}
	secret, err := httpapi.ReadSecret(k.ClientSecretFile)
	if err != nil {
		return s, err
	}
	var auth struct {
		Token string `json:"access_token"`
		Type  string `json:"token_type"`
	}
	err = k.request(ctx, http.MethodPost, k.Issuer+"/protocol/openid-connect/token", "",
		url.Values{"grant_type": {"client_credentials"}, "client_id": {k.ClientID}, "client_secret": {secret}}, &auth)
	if err != nil {
		return s, err
	}
	if auth.Token == "" || !strings.EqualFold(auth.Type, "Bearer") {
		return s, errors.New("Keycloak returned an invalid service token")
	}
	first, err := k.read(ctx, auth.Token)
	if err != nil {
		return s, err
	}
	second, err := k.read(ctx, auth.Token)
	if err != nil {
		return s, err
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		return s, errors.New("Keycloak directory changed between enumeration passes")
	}
	digest := sha256.Sum256(b)
	s.Users, s.Complete, s.Revision = second, true, hex.EncodeToString(digest[:])
	return s, nil
}
