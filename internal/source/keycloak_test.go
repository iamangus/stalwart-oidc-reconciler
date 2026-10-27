package source

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/httpapi"
)

func TestKeycloakSnapshots(t *testing.T) {
	for _, mode := range []string{"stable", "empty", "service account", "token denied", "token redirect", "bad token", "bad count", "null count", "too many", "truncated", "duplicate", "unknown enabled", "count changed", "same-count mutation", "bad JSON", "organization", "membership changed", "bad member", "null members", "multiple claims"} {
		t.Run(mode, func(t *testing.T) {
			counts, pages := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/realms/apps/protocol/openid-connect/token" {
					if r.Method != http.MethodPost || r.ParseForm() != nil || r.Form.Get("client_secret") != "private-test-secret" || r.Form.Get("client_id") != "reader" || r.Form.Get("grant_type") != "client_credentials" {
						t.Error("incorrect token request")
					}
					switch mode {
					case "token denied":
						w.WriteHeader(401)
					case "token redirect":
						w.Header().Set("Location", "/unexpected")
						w.WriteHeader(302)
					case "bad token":
						_, _ = w.Write([]byte(`{"access_token":"","token_type":"Bearer"}`))
					default:
						_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer"}`))
					}
					return
				}
				if r.Header.Get("Authorization") != "Bearer test-token" || r.Method != http.MethodGet {
					t.Error("credential forwarded or unexpected write")
				}
				if r.URL.Path == "/admin/realms/apps/users/count" {
					if mode == "null count" {
						_, _ = w.Write([]byte("null"))
						return
					}
					counts++
					n := 2
					switch mode {
					case "empty":
						n = 0
					case "bad count":
						n = -1
					case "too many":
						n = 3
					case "count changed":
						if counts > 1 {
							n = 1
						}
					}
					_ = json.NewEncoder(w).Encode(n)
					return
				}
				if r.URL.Path == "/admin/realms/apps/organizations/org/members" {
					if mode == "null members" {
						_, _ = w.Write([]byte("null"))
						return
					}
					if r.URL.Query().Get("first") == "0" {
						id := "u0"
						if mode == "bad member" {
							id = "unknown"
						}
						if mode == "membership changed" && pages > 2 {
							id = "u1"
						}
						_ = json.NewEncoder(w).Encode([]any{map[string]string{"id": id}})
					} else {
						_, _ = w.Write([]byte("[]"))
					}
					return
				}
				if r.URL.Path == "/admin/realms/apps/organizations/org/members/count" {
					_, _ = w.Write([]byte("1"))
					return
				}
				if r.URL.Path != "/admin/realms/apps/users" {
					t.Error("unexpected endpoint or followed redirect")
					w.WriteHeader(404)
					return
				}
				pages++
				if r.URL.Query().Get("max") != "1" || r.URL.Query().Get("briefRepresentation") != "false" {
					t.Error("unbounded or brief enumeration")
				}
				if mode == "bad JSON" {
					_, _ = w.Write([]byte("private-test-secret"))
					return
				}
				if mode == "truncated" {
					_, _ = w.Write([]byte("[]"))
					return
				}
				first, _ := strconv.Atoi(r.URL.Query().Get("first"))
				user := map[string]any{"id": "u" + strconv.Itoa(first), "firstName": "Alice", "lastName": "Example", "enabled": true, "emailVerified": true, "requiredActions": []string{}, "attributes": map[string][]string{"mail_address": {"alice.example@example.com"}}}
				if mode == "multiple claims" {
					user["attributes"] = map[string][]string{"mail_address": {"a@example.com", "b@example.com"}}
				}
				if first == 1 {
					user["enabled"] = false
				}
				if mode == "duplicate" {
					user["id"] = "same"
				}
				if mode == "unknown enabled" {
					delete(user, "enabled")
				}
				if mode == "service account" && first == 1 {
					user["serviceAccountClientId"] = "reader"
				}
				if mode == "same-count mutation" && pages > 2 {
					user["firstName"] = "Changed"
				}
				_ = json.NewEncoder(w).Encode([]any{user})
			}))
			defer server.Close()
			secret := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(secret, []byte("private-test-secret\n"), 0600); err != nil {
				t.Fatal(err)
			}
			client := httpapi.New(server.URL, "", time.Second).HTTP
			client.Transport = server.Client().Transport
			k := Keycloak{HTTP: client, Base: server.URL, Issuer: server.URL + "/realms/apps", Realm: "apps", ClientID: "reader", ClientSecretFile: secret, PageSize: 1, MaxUsers: 2}
			if mode == "organization" || mode == "membership changed" || mode == "bad member" || mode == "null members" {
				k.OrganizationID = "org"
			}
			s, err := k.Snapshot(context.Background())
			ok := mode == "stable" || mode == "empty" || mode == "service account" || mode == "organization"
			if ok {
				if err != nil || !s.Complete || counts != 4 || s.Revision == "" {
					t.Fatalf("snapshot incomplete: %v", err)
				}
				if mode == "stable" && (len(s.Users) != 2 || !s.Users[0].Active || s.Users[1].Active) {
					t.Fatal("incorrect active state")
				}
				if mode == "service account" && s.Users[1].Human {
					t.Fatal("service account treated as human")
				}
				if mode == "organization" && (!s.Users[0].OrganizationMember || s.Users[1].OrganizationMember || s.Users[0].OnboardingPending) {
					t.Fatal("wrong signup membership/readiness")
				}
			} else if err == nil || s.Complete || strings.Contains(err.Error(), "private-test-secret") {
				t.Fatalf("unsafe failure: %v", err)
			}
		})
	}
}

func TestKeycloakPublisherUsesOnlyRestrictedEndpoint(t *testing.T) {
	for _, status := range []int{204, 200, 401, 403, 409, 500, 302} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			writes := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/realms/apps/protocol/openid-connect/token" {
					if r.ParseForm() != nil || r.Form.Get("client_id") != "publisher" {
						t.Error("wrong credentials")
					}
					_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer"}`))
					return
				}
				if r.URL.Path != "/realms/apps/srvd-mail/users/user-id/address" || r.Method != http.MethodPut || r.Header.Get("Authorization") != "Bearer token" {
					t.Error("unexpected general API or redirect")
				}
				var body map[string]string
				_ = json.NewDecoder(r.Body).Decode(&body)
				if len(body) != 1 || body["address"] != "alice.example@example.com" {
					t.Error("unexpected mutation fields")
				}
				writes++
				w.Header().Set("Location", "/forbidden")
				w.WriteHeader(status)
			}))
			defer server.Close()
			secret := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(secret, []byte("secret"), 0600); err != nil {
				t.Fatal(err)
			}
			client := httpapi.New(server.URL, "", time.Second).HTTP
			client.Transport = server.Client().Transport
			k := Keycloak{HTTP: client, Issuer: server.URL + "/realms/apps", ClientID: "publisher", ClientSecretFile: secret}
			err := k.PublishAddress(context.Background(), "user-id", "alice.example@example.com")
			if (err == nil) != (status == 204) || writes != 1 {
				t.Fatalf("unsafe publication: %v", err)
			}
		})
	}
}
