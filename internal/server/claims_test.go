package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/state"
)

func signed(body, key string, at time.Time) string {
	timestamp := fmt.Sprint(at.Unix())
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(timestamp + "." + body))
	return "t=" + timestamp + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestSignatureFreshnessAndTampering(t *testing.T) {
	now := time.Now()
	header := signed(`{"test":true}`, "secret", now)
	if err := VerifySignature(header, []byte(`{"test":true}`), "secret", now); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"", header + ",t=1", header + ",other=1", signed("body", "secret", now.Add(-10*time.Minute)), signed("body", "secret", now.Add(2*time.Minute))} {
		if VerifySignature(h, []byte("body"), "secret", now) == nil {
			t.Fatal("bad signature accepted")
		}
	}
	if VerifySignature(header, []byte(`{"test":false}`), "secret", now) == nil {
		t.Fatal("tampering accepted")
	}
}

func TestClaimsAreScopedFreshAndFailClosed(t *testing.T) {
	for _, mode := range []string{"ok", "userinfo", "production access token", "production userinfo", "wrong signature", "wrong client", "unrelated function and client", "wrong org", "stale", "suspended", "pending transition", "missing", "dry run", "bad function"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.json")
			keyfile := filepath.Join(dir, "key")
			_ = os.WriteFile(keyfile, []byte("test-secret\n"), 0600)
			now := time.Now().UTC()
			store, err := state.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			d := state.Data{Version: 1, Fingerprint: "f", LastComplete: now, Entries: map[string]*state.Entry{"alice": {AccountID: "1", Address: "alice.example@example.com", Status: "active"}}}
			client, org, function := "client1", "org1", "PreAccessToken"
			want := http.StatusOK
			h := Claims{StateFile: path, Fingerprint: "f", Scope: "org1", KeyFile: keyfile, ClientIDs: []string{"client1"}, ClaimName: "mail_address", MaxStale: 15 * time.Minute, Apply: true, Now: func() time.Time { return now }}
			switch mode {
			case "userinfo":
				function = "preuserinfo"
			case "production access token":
				function = "function/preaccesstoken"
			case "production userinfo":
				function = "function/preuserinfo"
			case "unrelated function and client":
				client, function, org = "other", "function/future-trigger", "other-org"
				d.LastComplete = now.Add(-time.Hour)
			case "wrong signature":
				want = 401
			case "wrong client":
				client = "other"
			case "wrong org":
				org = "other"
				want = 403
			case "stale":
				d.LastComplete = now.Add(-time.Hour)
				want = 503
			case "suspended":
				d.Entries["alice"].Status = "suspended"
				want = 403
			case "pending transition":
				d.Entries["alice"].Transition = "suspend"
				want = 403
			case "missing":
				delete(d.Entries, "alice")
				want = 403
			case "dry run":
				h.Apply = false
				want = 503
			case "bad function":
				function = "unrelated"
				want = 400
			}
			if err := store.Save(d); err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf(`{"function":%q,"user":{"id":"alice"},"org":{"id":%q},"application":{"client_id":%q}}`, function, org, client)
			r := httptest.NewRequest("POST", "/hooks/zitadel/claims", strings.NewReader(body))
			signature := signed(body, "test-secret", now)
			if mode == "wrong signature" {
				signature = signed(body, "other", now)
			}
			r.Header.Set("Zitadel-Signature", signature)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatalf("HTTP %d want %d: %s", w.Code, want, w.Body.String())
			}
			if mode == "ok" || mode == "userinfo" || strings.HasPrefix(mode, "production ") {
				if !strings.Contains(w.Body.String(), `"mail_address"`) || !strings.Contains(w.Body.String(), "alice.example@example.com") {
					t.Fatal(w.Body.String())
				}
			}
			if (mode == "wrong client" || mode == "unrelated function and client") && strings.Contains(w.Body.String(), "alice.example") {
				t.Fatal("claim leaked to unrelated client")
			}
		})
	}
}
