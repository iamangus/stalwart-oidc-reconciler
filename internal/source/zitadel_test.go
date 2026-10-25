package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/httpapi"
)

func TestZitadelPaginationAndSafety(t *testing.T) {
	for _, mode := range []string{"ok", "truncated", "changing sequence", "wrong org", "unknown state", "duplicate", "wrong count", "http failure"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/v2/users" || r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("bad request")
				}
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				queries := body["queries"].([]any)
				if queries[0].(map[string]any)["organizationIdQuery"].(map[string]any)["organizationId"] != "org" {
					t.Error("unscoped query")
				}
				if mode == "http failure" {
					w.WriteHeader(503)
					return
				}
				id, owner, status, sequence, total := "alice", "org", "USER_STATE_ACTIVE", "5", 2
				if calls == 2 {
					id = "bot"
				}
				if mode == "changing sequence" && calls == 2 {
					sequence = "6"
				}
				if mode == "wrong org" {
					owner = "other"
				}
				if mode == "unknown state" {
					status = "USER_STATE_FUTURE"
				}
				if mode == "duplicate" {
					id = "alice"
				}
				if mode == "wrong count" {
					total = 0
				}
				result := []any{map[string]any{"userId": id, "state": status, "details": map[string]any{"resourceOwner": owner}}}
				if calls == 1 {
					result[0].(map[string]any)["human"] = map[string]any{"profile": map[string]any{"givenName": "Alice", "familyName": "Example", "displayName": "Alice Example"}}
				}
				if mode == "truncated" && calls == 2 {
					result = []any{}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"details": map[string]any{"totalResult": fmt.Sprint(total), "processedSequence": sequence}, "result": result})
			}))
			defer srv.Close()
			file := filepath.Join(t.TempDir(), "token")
			_ = os.WriteFile(file, []byte("test-token\n"), 0600)
			z := Zitadel{API: httpapi.New(srv.URL, file, time.Second), Issuer: "https://id.example.com", Organization: "org", PageSize: 1, MaxUsers: 100}
			s, err := z.Snapshot(context.Background())
			if mode == "ok" {
				if err != nil || !s.Complete || len(s.Users) != 2 || !s.Users[0].Human || s.Users[1].Human || s.Users[0].GivenName != "Alice" {
					t.Fatalf("%+v %v", s, err)
				}
			} else if err == nil || s.Complete {
				t.Fatal("unsafe snapshot accepted")
			}
		})
	}
}

func TestCountAcceptsProtoJSONStringsAndNumbers(t *testing.T) {
	for _, s := range []string{`"123"`, `123`} {
		var c count
		if json.Unmarshal([]byte(s), &c) != nil || c != 123 {
			t.Fatal(s)
		}
	}
	for _, s := range []string{`-1`, `null`, `"bad"`, `1.2`} {
		var c count
		if json.Unmarshal([]byte(s), &c) == nil {
			t.Fatal(s)
		}
	}
}
