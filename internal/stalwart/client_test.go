package stalwart

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/httpapi"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/mailbox"
)

func apiFixture(t *testing.T, handle func(string, map[string]any) (string, any)) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jmap" || r.Header.Get("Authorization") != "Bearer api-secret" {
			t.Error("incorrect endpoint/auth")
		}
		var req struct {
			Calls [][]json.RawMessage `json:"methodCalls"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Calls) != 1 {
			t.Error("invalid request")
			return
		}
		var method string
		var args map[string]any
		_ = json.Unmarshal(req.Calls[0][0], &method)
		_ = json.Unmarshal(req.Calls[0][1], &args)
		if strings.Contains(string(req.Calls[0][1]), `"credentials"`) && method == "x:Account/get" {
			t.Error("reading credentials")
		}
		name, body := handle(method, args)
		_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{name, body, "r1"}}})
	}))
	t.Cleanup(srv.Close)
	path := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(path, []byte("api-secret"), 0600)
	return &Client{API: httpapi.New(srv.URL, path, time.Second), JMAPPath: "/jmap", MaxAccounts: 100}
}

func TestSnapshotNeverReadsCredentialsAndRequiresCompleteResults(t *testing.T) {
	for _, mode := range []string{"ok", "truncated", "not found", "duplicate", "wrong domain"} {
		t.Run(mode, func(t *testing.T) {
			c := apiFixture(t, func(method string, args map[string]any) (string, any) {
				switch method {
				case "x:Domain/get":
					name := "example.com"
					if mode == "wrong domain" {
						name = "other.com"
					}
					return method, map[string]any{"list": []any{map[string]any{"id": "d", "name": name}}}
				case "x:Account/query":
					ids := []string{"1"}
					total := 1
					if mode == "truncated" {
						ids = nil
					}
					if mode == "duplicate" {
						ids = []string{"1", "1"}
						total = 2
					}
					return method, map[string]any{"ids": ids, "total": total, "position": 0}
				case "x:Account/get":
					if mode == "not found" {
						return method, map[string]any{"list": []any{}, "notFound": []string{"1"}}
					}
					return method, map[string]any{"list": []any{map[string]any{"id": "1", "@type": "User", "name": "alice", "domainId": "d", "permissions": map[string]any{"@type": "Inherit"}, "roles": map[string]any{"@type": "User"}}}}
				}
				t.Fatal(method)
				return "", nil
			})
			c.DomainID, c.Domain = "d", "example.com"
			s, err := c.Snapshot(context.Background())
			if mode == "ok" {
				if err != nil || len(s.Accounts) != 1 {
					t.Fatalf("%+v %v", s, err)
				}
			} else if err == nil {
				t.Fatal("incomplete destination accepted")
			}
		})
	}
}

func TestHTTP200JMAPErrorsAndPartialWritesAreErrors(t *testing.T) {
	for _, mode := range []string{"method error", "notCreated", "notUpdated"} {
		t.Run(mode, func(t *testing.T) {
			c := apiFixture(t, func(method string, args map[string]any) (string, any) {
				if mode == "method error" {
					return "error", map[string]any{"type": "forbidden", "description": "api-secret must not be logged"}
				}
				if method == "x:Account/get" {
					return method, map[string]any{"list": []any{map[string]any{"id": "1", "@type": "User", "name": "alice", "domainId": "d"}}}
				}
				return method, map[string]any{mode: map[string]any{"new": map[string]any{"type": "forbidden"}}}
			})
			var err error
			if mode == "notUpdated" {
				err = c.Update(context.Background(), mailbox.Account{ID: "1", Type: "User", Name: "alice", DomainID: "d"}, map[string]any{"description": "new"})
			} else {
				_, err = c.Create(context.Background(), map[string]any{})
			}
			if err == nil || strings.Contains(err.Error(), "api-secret") {
				t.Fatal("accepted or leaked API error", err)
			}
		})
	}
}

func TestUpdateChecksForDriftBeforeWriting(t *testing.T) {
	writes := 0
	c := apiFixture(t, func(method string, args map[string]any) (string, any) {
		if method == "x:Account/set" {
			writes++
		}
		return method, map[string]any{"list": []any{map[string]any{"id": "1", "@type": "User", "name": "alice", "domainId": "d", "description": "changed"}}}
	})
	err := c.Update(context.Background(), mailbox.Account{ID: "1", Type: "User", Name: "alice", DomainID: "d"}, map[string]any{"description": "new"})
	if err == nil || writes != 0 {
		t.Fatal("stale write accepted")
	}
}
