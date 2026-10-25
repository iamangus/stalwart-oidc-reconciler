package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/httpapi"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/state"
)

type Claims struct {
	StateFile   string
	Fingerprint string
	Scope       string
	KeyFile     string
	ClientIDs   []string
	ClaimName   string
	MaxStale    time.Duration
	Apply       bool
	Now         func() time.Time
}

// VerifySignature implements ZITADEL's t=<seconds>,v1=<hex HMAC-SHA256> header
// and additionally enforces a five-minute timestamp window. Secret stays opaque
// (not base64 decoded), matching ZITADEL's documented signing format.
func VerifySignature(header string, body []byte, key string, now time.Time) error {
	var timestamp, signature string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return errors.New("invalid signature format")
		}
		switch k {
		case "t":
			if timestamp != "" {
				return errors.New("duplicate timestamp")
			}
			timestamp = v
		case "v1":
			if signature != "" {
				return errors.New("duplicate signature")
			}
			signature = v
		default:
			return errors.New("unknown signature field")
		}
	}
	t, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || now.Sub(time.Unix(t, 0)) > 5*time.Minute || time.Unix(t, 0).Sub(now) > time.Minute {
		return errors.New("signature timestamp expired or invalid")
	}
	got, err := hex.DecodeString(signature)
	if err != nil || len(got) != sha256.Size {
		return errors.New("invalid signature encoding")
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), got) {
		return errors.New("invalid signature")
	}
	return nil
}

func (c Claims) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	key, err := httpapi.ReadSecret(c.KeyFile)
	if err != nil {
		http.Error(w, "signing key unavailable", http.StatusServiceUnavailable)
		return
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now()
	}
	header := r.Header.Get("Zitadel-Signature")
	if VerifySignature(header, body, key, now) != nil {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var request struct {
		Function string `json:"function"`
		User     struct {
			ID string `json:"id"`
		} `json:"user"`
		Org struct {
			ID string `json:"id"`
		} `json:"org"`
		Application struct {
			ClientID string `json:"client_id"`
		} `json:"application"`
	}
	if json.Unmarshal(body, &request) != nil {
		http.Error(w, "invalid action payload", http.StatusBadRequest)
		return
	}
	allowed := false
	for _, id := range c.ClientIDs {
		if id == request.Application.ClientID {
			allowed = true
		}
	}
	if !allowed {
		// Actions can be installed instance-wide. Leave unrelated applications alone.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"append_claims":[]}`))
		return
	}
	// ZITADEL 4.20 sends the execution aggregate ID (function/preuserinfo or
	// function/preaccesstoken), not just the function name used by its API.
	// Keep bare names compatible with earlier payloads and fixtures.
	function := strings.TrimPrefix(strings.ToLower(request.Function), "function/")
	if function != "preuserinfo" && function != "preaccesstoken" {
		http.Error(w, "unsupported action function", http.StatusBadRequest)
		return
	}
	if request.User.ID == "" {
		http.Error(w, "mail action requires a user identity", http.StatusBadRequest)
		return
	}
	if request.Org.ID != c.Scope {
		http.Error(w, "organization not eligible for mail", http.StatusForbidden)
		return
	}
	d, err := state.Read(c.StateFile)
	if !c.Apply || err != nil || d.Fingerprint != c.Fingerprint || d.LastComplete.IsZero() || now.Sub(d.LastComplete) > c.MaxStale || d.LastComplete.After(now.Add(time.Minute)) {
		http.Error(w, "mail directory not ready or stale", http.StatusServiceUnavailable)
		return
	}
	entry := d.Entries[request.User.ID]
	if entry == nil || entry.AccountID == "" || entry.Status != "active" || entry.Transition != "" || entry.MissingSince != nil {
		http.Error(w, "mailbox not provisioned or not active", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"append_claims": []any{
		map[string]any{"key": c.ClaimName, "value": entry.Address},
	}})
}
