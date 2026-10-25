// Package httpapi provides bounded, credential-safe HTTP calls.
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const MaxBody = 16 << 20

type Client struct {
	Base      string
	TokenFile string
	HTTP      *http.Client
}

func ValidateURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("endpoint must be an absolute URL without credentials, query, or fragment")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return errors.New("endpoint must use HTTPS (allow_http is required for a trusted internal HTTP endpoint)")
	}
	return nil
}

func New(base, tokenFile string, timeout time.Duration) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), TokenFile: tokenFile, HTTP: &http.Client{
		Timeout: timeout,
		// Never forward credentials or writes to a redirected endpoint.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func ReadSecret(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read credential file: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil || len(b) > 64<<10 {
		return "", errors.New("credential file unreadable or too large")
	}
	s := strings.TrimSpace(string(b))
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return "", errors.New("credential must be a nonempty single line")
	}
	return s, nil
}

// Call deliberately does not retry: a timed-out mutation may have succeeded.
// Callers reconcile again after reads rather than replay uncertain writes.
func (c *Client) Call(ctx context.Context, path string, input, output any) error {
	b, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+path, bytes.NewReader(b))
	if err != nil {
		return errors.New("construct API request")
	}
	if c.TokenFile != "" {
		token, err := ReadSecret(c.TokenFile)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// net/http errors may contain URLs or headers. Do not log those.
		return errors.New("API transport failed (request outcome may be unknown)")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API returned HTTP %d", resp.StatusCode)
	}
	b, err = io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil || len(b) > MaxBody {
		return errors.New("API response unreadable or exceeds size limit")
	}
	if err := json.Unmarshal(b, output); err != nil {
		return errors.New("API returned malformed JSON")
	}
	return nil
}
