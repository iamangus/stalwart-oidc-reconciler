package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/httpapi"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/source"
)

// This opt-in test is read-only. The supplied token must have complete user-list
// permission in the explicitly selected organization. It never prints users.
func TestRealZitadelSnapshot(t *testing.T) {
	if os.Getenv("ZITADEL_INTEGRATION_ALLOW_READ") != "1" {
		t.Skip("requires explicit ZITADEL organization and read credential")
	}
	issuer, scope, token := os.Getenv("ZITADEL_TEST_ISSUER"), os.Getenv("ZITADEL_TEST_ORG"), os.Getenv("ZITADEL_TEST_TOKEN_FILE")
	if issuer == "" || scope == "" || token == "" {
		t.Fatal("missing ZITADEL integration environment")
	}
	z := &source.Zitadel{API: httpapi.New(issuer, token, 30*time.Second), Issuer: issuer, Organization: scope, PageSize: 1, MaxUsers: 1000}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	snapshot, err := z.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Validate(issuer, scope, 1000); err != nil {
		t.Fatal(err)
	}
	humans := 0
	for _, u := range snapshot.Users {
		if u.Human {
			humans++
		}
	}
	t.Logf("PASS: complete scoped ZITADEL snapshot, %d identities, %d humans; no mutations", len(snapshot.Users), humans)
}
