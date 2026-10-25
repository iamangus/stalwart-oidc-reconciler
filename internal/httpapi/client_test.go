package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNeverFollowRedirectOrLogResponseSecrets(t *testing.T) {
	for _, status := range []int{302, 401, 503} {
		requests := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(status)
			_, _ = w.Write([]byte("super-secret"))
		}))
		c := New(srv.URL, "", time.Second)
		var out any
		err := c.Call(context.Background(), "/api", map[string]any{}, &out)
		srv.Close()
		if err == nil || strings.Contains(err.Error(), "super-secret") || requests != 1 {
			t.Fatal(err, requests)
		}
	}
}

func TestSecretRotationAndValidation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(file, []byte("one\n"), 0600)
	if s, e := ReadSecret(file); e != nil || s != "one" {
		t.Fatal(s, e)
	}
	_ = os.WriteFile(file, []byte("two"), 0600)
	if s, _ := ReadSecret(file); s != "two" {
		t.Fatal("rotation not read")
	}
	_ = os.WriteFile(file, []byte("bad\ninjection"), 0600)
	if _, e := ReadSecret(file); e == nil {
		t.Fatal("multiline token accepted")
	}
	for _, url := range []string{"http://example.com", "https://user:secret@example.com", "https://example.com?token=secret", "ftp://example.com"} {
		if ValidateURL(url, false) == nil {
			t.Fatal(url)
		}
	}
	if ValidateURL("http://127.0.0.1:8080", true) != nil || ValidateURL("https://example.com", false) != nil {
		t.Fatal("valid URL rejected")
	}
}
