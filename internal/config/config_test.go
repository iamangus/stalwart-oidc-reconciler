package config

import "testing"

func example() Config {
	c := Defaults()
	c.Source.Kind = "zitadel"
	c.Source.Issuer = "https://id.example.com"
	c.Source.URL = c.Source.Issuer
	c.Source.Scope = "org"
	c.Source.TokenFile = "/run/secrets/source"
	c.Stalwart.URL = "https://mail.example.com"
	c.Stalwart.TokenFile = "/run/secrets/target"
	c.Stalwart.Domain = "example.com"
	c.Stalwart.DomainID = "d"
	return c
}

func TestConfigurationSafety(t *testing.T) {
	if err := example().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"http", "unknown adapter", "bad duration", "relative state", "missing org", "bad domain", "fraction", "reserved claim"} {
		c := example()
		switch mode {
		case "http":
			c.Source.URL = "http://id.example.com"
		case "unknown adapter":
			c.Source.Kind = "oidc"
		case "bad duration":
			c.Interval = "0s"
		case "relative state":
			c.StateFile = "./state.json"
		case "missing org":
			c.Source.Scope = ""
		case "bad domain":
			c.Stalwart.Domain = "example..com"
		case "fraction":
			c.Policy.MaxSuspendFraction = 2
		case "reserved claim":
			c.Claims.Enabled = true
			c.Claims.SigningKeyFile = "/secret"
			c.Claims.ClientIDs = []string{"c"}
			c.Claims.ClaimName = "email"
		}
		if c.Validate() == nil {
			t.Fatal("accepted", mode)
		}
	}
}

func TestKeycloakConfiguration(t *testing.T) {
	c := example()
	c.Source.Kind, c.Source.Scope = "keycloak", "apps"
	c.Source.URL, c.Source.Issuer = "https://id.example.com/auth", "https://id.example.com/auth/realms/apps"
	c.Source.ClientID, c.Source.ClientSecretFile = "reader", "/run/reader/secret"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"wrong issuer", "no secret", "bad realm", "http"} {
		d := c
		switch mode {
		case "wrong issuer":
			d.Source.Issuer += "-other"
		case "no secret":
			d.Source.ClientSecretFile = ""
		case "bad realm":
			d.Source.Scope = "../other"
		case "http":
			d.Source.URL = "http://id.example.com/auth"
		}
		if d.Validate() == nil {
			t.Fatal("accepted", mode)
		}
	}
	p := c.ReconcilePolicy()
	old := p.Fingerprint()
	p.IncludeIDs = []string{"pilot"}
	if p.Fingerprint() == old {
		t.Fatal("include scope not fingerprinted")
	}
}
