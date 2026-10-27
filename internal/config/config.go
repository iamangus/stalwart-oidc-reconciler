package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/httpapi"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/reconcile"
)

type Config struct {
	StateFile    string `json:"state_file"`
	Listen       string `json:"listen"`
	Interval     string `json:"interval"`
	CycleTimeout string `json:"cycle_timeout"`
	HTTPTimeout  string `json:"http_timeout"`
	Source       struct {
		Kind             string `json:"kind"`
		Issuer           string `json:"issuer"`
		Scope            string `json:"scope"`
		URL              string `json:"url"`
		TokenFile        string `json:"token_file"`
		AllowHTTP        bool   `json:"allow_http"`
		File             string `json:"file"`
		PageSize         int    `json:"page_size"`
		ClientID         string `json:"client_id"`
		ClientSecretFile string `json:"client_secret_file"`
		OrganizationID   string `json:"organization_id"`
	} `json:"source"`
	Stalwart struct {
		URL         string `json:"url"`
		TokenFile   string `json:"token_file"`
		AllowHTTP   bool   `json:"allow_http"`
		JMAPPath    string `json:"jmap_path"`
		Domain      string `json:"domain"`
		DomainID    string `json:"domain_id"`
		QuotaBytes  int64  `json:"quota_bytes"`
		MaxAccounts int    `json:"max_accounts"`
	} `json:"stalwart"`
	Policy struct {
		MaxUsers           int               `json:"max_users"`
		MissingGrace       string            `json:"missing_grace"`
		MaxSuspensions     int               `json:"max_suspensions"`
		MaxSuspendFraction float64           `json:"max_suspend_fraction"`
		AllowEmpty         bool              `json:"allow_empty"`
		ExcludeIDs         []string          `json:"exclude_ids"`
		IncludeIDs         []string          `json:"include_ids"`
		AddressOverrides   map[string]string `json:"address_overrides"`
		NumericSuffixes    bool              `json:"numeric_suffixes"`
	} `json:"policy"`
	Claims struct {
		Enabled        bool     `json:"enabled"`
		SigningKeyFile string   `json:"signing_key_file"`
		ClientIDs      []string `json:"client_ids"`
		ClaimName      string   `json:"claim_name"`
		MaxStale       string   `json:"max_stale"`
	} `json:"zitadel_claims"`
	Publisher struct {
		Enabled          bool   `json:"enabled"`
		ClientID         string `json:"client_id"`
		ClientSecretFile string `json:"client_secret_file"`
	} `json:"keycloak_publisher"`
}

func Defaults() Config {
	var c Config
	c.StateFile, c.Listen, c.Interval = "/data/state.json", ":8080", "1m"
	c.CycleTimeout, c.HTTPTimeout = "5m", "30s"
	c.Source.PageSize = 100
	c.Stalwart.JMAPPath, c.Stalwart.MaxAccounts = "/jmap", 10000
	c.Stalwart.QuotaBytes = 5 << 30
	c.Policy.MaxUsers, c.Policy.MissingGrace = 10000, "24h"
	c.Policy.MaxSuspensions, c.Policy.MaxSuspendFraction = 5, 0.5
	c.Claims.ClaimName, c.Claims.MaxStale = "mail_address", "15m"
	return c
}

func Load(path string) (Config, error) {
	c := Defaults()
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("invalid configuration: %w", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("configuration contains trailing data")
	}
	return c, c.Validate()
}

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

func (c Config) Validate() error {
	if c.StateFile == "" || !filepath.IsAbs(c.StateFile) {
		return errors.New("state_file must be an absolute path")
	}
	if c.Source.Scope == "" || httpapi.ValidateURL(c.Source.Issuer, false) != nil || strings.HasSuffix(c.Source.Issuer, "/") {
		return errors.New("source requires an HTTPS issuer without a trailing slash and a nonempty scope")
	}
	switch c.Source.Kind {
	case "zitadel":
		if c.Source.TokenFile == "" || httpapi.ValidateURL(c.Source.URL, c.Source.AllowHTTP) != nil || c.Source.PageSize < 1 || c.Source.PageSize > 1000 {
			return errors.New("invalid ZITADEL URL, token file, or page_size")
		}
	case "file":
		if c.Source.File == "" {
			return errors.New("file source requires file path")
		}
	case "keycloak":
		if httpapi.ValidateURL(c.Source.URL, false) != nil || c.Source.ClientID == "" || c.Source.ClientSecretFile == "" ||
			!regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(c.Source.Scope) ||
			c.Source.Issuer != strings.TrimRight(c.Source.URL, "/")+"/realms/"+c.Source.Scope || c.Source.PageSize < 1 || c.Source.PageSize > 1000 {
			return errors.New("invalid Keycloak HTTPS URL, matching realm/issuer, client credentials or page_size")
		}
	default:
		return errors.New("source.kind must be zitadel, keycloak or file")
	}
	if httpapi.ValidateURL(c.Stalwart.URL, c.Stalwart.AllowHTTP) != nil || c.Stalwart.TokenFile == "" {
		return errors.New("invalid Stalwart URL or missing token file")
	}
	if c.Stalwart.JMAPPath == "" || !strings.HasPrefix(c.Stalwart.JMAPPath, "/") || strings.ContainsAny(c.Stalwart.JMAPPath, "?#") {
		return errors.New("jmap_path must be an absolute path without query/fragment")
	}
	if !domainPattern.MatchString(c.Stalwart.Domain) || !strings.Contains(c.Stalwart.Domain, ".") || strings.Contains(c.Stalwart.Domain, "..") || c.Stalwart.DomainID == "" {
		return errors.New("invalid lowercase mail domain or missing Stalwart domain_id")
	}
	for _, label := range strings.Split(c.Stalwart.Domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid DNS label in mail domain")
		}
	}
	if c.Stalwart.QuotaBytes < 1 || c.Policy.MaxUsers < 1 || c.Stalwart.MaxAccounts < 1 || c.Policy.MaxSuspensions < 0 || c.Policy.MaxSuspendFraction < 0 || c.Policy.MaxSuspendFraction > 1 {
		return errors.New("invalid quota or safety threshold")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return errors.New("listen must be host:port")
	}
	for _, duration := range []string{c.Interval, c.CycleTimeout, c.HTTPTimeout, c.Policy.MissingGrace, c.Claims.MaxStale} {
		v, err := time.ParseDuration(duration)
		if err != nil || v <= 0 {
			return errors.New("durations must be positive Go duration strings")
		}
	}
	if c.Claims.Enabled && (c.Source.Kind != "zitadel" || c.Claims.SigningKeyFile == "" || len(c.Claims.ClientIDs) == 0 || !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`).MatchString(c.Claims.ClaimName)) {
		return errors.New("ZITADEL claims require zitadel source, signing_key_file, client_ids, and a safe claim_name")
	}
	if c.Claims.Enabled {
		switch c.Claims.ClaimName {
		case "sub", "iss", "aud", "email", "email_verified", "preferred_username", "scope", "exp", "iat", "nbf", "nonce", "sid":
			return errors.New("claim_name must be a custom claim, not a standard identity/security claim")
		}
	}
	ids := map[string]bool{}
	if c.Source.OrganizationID != "" && (c.Source.Kind != "keycloak" || !regexp.MustCompile(`^[a-zA-Z0-9-]+$`).MatchString(c.Source.OrganizationID)) {
		return errors.New("organization_id requires Keycloak and an immutable organization ID")
	}
	if c.Publisher.Enabled && (c.Source.Kind != "keycloak" || c.Publisher.ClientID == "" || c.Publisher.ClientID == c.Source.ClientID || c.Publisher.ClientSecretFile == "" || c.Publisher.ClientSecretFile == c.Source.ClientSecretFile) {
		return errors.New("Keycloak publisher requires distinct client credentials and a Keycloak source")
	}
	for _, id := range c.Policy.IncludeIDs {
		if id == "" || ids[id] {
			return errors.New("include_ids must contain nonempty unique subject IDs")
		}
		ids[id] = true
	}
	return nil
}

func Duration(s string) time.Duration { d, _ := time.ParseDuration(s); return d }

func (c Config) ReconcilePolicy() reconcile.Policy {
	return reconcile.Policy{
		Issuer: c.Source.Issuer, Scope: c.Source.Scope, SourceKind: c.Source.Kind,
		Destination: strings.TrimRight(c.Stalwart.URL, "/") + c.Stalwart.JMAPPath,
		Domain:      c.Stalwart.Domain, DomainID: c.Stalwart.DomainID, QuotaBytes: c.Stalwart.QuotaBytes,
		MaxUsers: c.Policy.MaxUsers, MissingGrace: Duration(c.Policy.MissingGrace),
		MaxSuspensions: c.Policy.MaxSuspensions, MaxSuspendFraction: c.Policy.MaxSuspendFraction,
		AllowEmpty: c.Policy.AllowEmpty, ExcludeIDs: c.Policy.ExcludeIDs, AddressOverrides: c.Policy.AddressOverrides,
		IncludeIDs:     c.Policy.IncludeIDs,
		OrganizationID: c.Source.OrganizationID, NumericSuffixes: c.Policy.NumericSuffixes,
	}
}
