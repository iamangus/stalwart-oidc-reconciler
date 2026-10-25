package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/httpapi"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/reconcile"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/source"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/stalwart"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/state"
)

// This test MUTATES an isolated test server. The Kubernetes fixture creates and
// destroys a dedicated namespace with no ingress and no production identities.
// Ordinary `go test ./...` skips it unless explicitly enabled.
func TestRealStalwartLifecycle(t *testing.T) {
	if os.Getenv("STALWART_INTEGRATION_ALLOW_WRITES") != "1" {
		t.Skip("requires an isolated Stalwart fixture; see tests/integration/kubernetes.py")
	}
	base, tokenFile, domainID := os.Getenv("STALWART_TEST_URL"), os.Getenv("STALWART_TEST_TOKEN_FILE"), os.Getenv("STALWART_TEST_DOMAIN_ID")
	if base == "" || tokenFile == "" || domainID == "" {
		t.Fatal("incomplete integration environment")
	}
	domain := os.Getenv("STALWART_TEST_DOMAIN")
	if !strings.HasSuffix(domain, ".example.com") {
		t.Fatal("integration test only permits subdomains of RFC-reserved example.com")
	}
	client := &stalwart.Client{API: httpapi.New(base, tokenFile, 30*time.Second), JMAPPath: "/jmap", MaxAccounts: 1000, Domain: domain, DomainID: domainID}
	dir := t.TempDir()
	inventory := filepath.Join(dir, "users.json")
	store, err := state.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	random := make([]byte, 6)
	_, _ = rand.Read(random)
	suffix := hex.EncodeToString(random)
	id := "test-" + suffix
	writeUsers := func(active bool) {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"complete": true, "issuer": "https://id.example.invalid", "scope": "test", "users": []any{map[string]any{"id": id, "given_name": "Reconciler", "family_name": suffix, "display_name": "Reconciler Integration Test", "human": true, "active": active}}})
		if os.WriteFile(inventory, b, 0600) != nil {
			t.Fatal("write inventory")
		}
	}
	writeUsers(true)
	e := &reconcile.Engine{Source: source.File{Path: inventory}, Target: client, Store: store, Policy: reconcile.Policy{
		Issuer: "https://id.example.invalid", Scope: "test", SourceKind: "file", Destination: base + "/jmap", Domain: domain, DomainID: domainID,
		QuotaBytes: 10 << 20, MaxUsers: 100, MaxSuspensions: 2, MaxSuspendFraction: 1, MissingGrace: time.Hour,
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	plan, err := e.Run(ctx, false)
	if err != nil || len(plan.Actions) != 1 {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	if _, err := e.Run(ctx, true); err != nil {
		t.Fatal("create:", err)
	}
	if plan, err := e.Run(ctx, true); err != nil || len(plan.Actions) != 0 {
		t.Fatalf("second run is not idempotent: %+v %v", plan, err)
	}
	d, _ := store.Load()
	entry := d.Entries[id]
	// Only the TEST harness installs a local password to prove suspension blocks
	// secondary/local credentials. The reconciler itself never writes passwords.
	password := "Aa1!" + suffix + suffix
	api := httpapi.New(base, tokenFile, 30*time.Second)
	jmap := func(method string, args any) map[string]any {
		t.Helper()
		var response struct {
			Methods [][]json.RawMessage `json:"methodResponses"`
		}
		err := api.Call(ctx, "/jmap", map[string]any{"using": []string{"urn:ietf:params:jmap:core", "urn:stalwart:jmap"}, "methodCalls": []any{[]any{method, args, "r1"}}}, &response)
		if err != nil || len(response.Methods) != 1 || len(response.Methods[0]) != 3 {
			t.Fatal("test JMAP call failed", err)
		}
		var got string
		_ = json.Unmarshal(response.Methods[0][0], &got)
		if got != method {
			t.Fatal("test JMAP method rejected", method)
		}
		var body map[string]any
		_ = json.Unmarshal(response.Methods[0][1], &body)
		return body
	}
	response := jmap("x:Account/set", map[string]any{"update": map[string]any{entry.AccountID: map[string]any{"credentials": map[string]any{"0": map[string]any{"@type": "Password", "secret": password}}}}})
	if _, ok := response["updated"].(map[string]any)[entry.AccountID]; !ok {
		t.Fatal("test credential setup failed")
	}
	checkAuth := func(want bool) {
		t.Helper()
		request, _ := http.NewRequestWithContext(ctx, "GET", base+"/api/account", nil)
		request.SetBasicAuth(entry.Address, password)
		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if want && resp.StatusCode != 200 {
			t.Fatalf("expected authentication success, got HTTP %d", resp.StatusCode)
		}
		if !want && resp.StatusCode != 401 && resp.StatusCode != 403 {
			t.Fatalf("suspended credential not denied: HTTP %d", resp.StatusCode)
		}
	}
	checkAuth(true)
	writeUsers(false)
	if _, err := e.Run(ctx, true); err != nil {
		t.Fatal("suspend:", err)
	}
	checkAuth(false)
	writeUsers(true)
	if _, err := e.Run(ctx, true); err != nil {
		t.Fatal("resume:", err)
	}
	checkAuth(true)
	if plan, err := e.Run(ctx, true); err != nil || len(plan.Actions) != 0 {
		t.Fatal("final run not idempotent", err)
	}
	// Verify dry-run has not written any local password into ownership state.
	stateBytes, _ := os.ReadFile(store.Path)
	if bytes.Contains(stateBytes, []byte(password)) {
		t.Fatal("credential leaked to reconciler state")
	}
	t.Log("PASS: real Community API domain validation, pre-provisioning, idempotence, suspension, local credential denial, and reactivation")
}
