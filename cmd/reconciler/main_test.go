package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCLIFlags(t *testing.T) {
	if err := run([]string{"--version"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--help"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--does-not-exist"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if err := run([]string{"unexpected"}); err == nil {
		t.Fatal("positional argument accepted")
	}
}

func TestDaemonHelper(t *testing.T) {
	if os.Getenv("RECONCILER_DAEMON_HELPER") != "1" {
		return
	}
	if err := run([]string{"--config", os.Getenv("RECONCILER_DAEMON_CONFIG")}); err != nil {
		t.Fatal(err)
	}
}

func TestDaemonHealthMetricsAndGracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Calls [][]json.RawMessage `json:"methodCalls"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var name string
		_ = json.Unmarshal(req.Calls[0][0], &name)
		var body any
		if name == "x:Domain/get" {
			body = map[string]any{"list": []any{map[string]any{"id": "d", "name": "example.com"}}}
		} else if name == "x:Account/query" {
			body = map[string]any{"ids": []string{}, "total": 0, "position": 0}
		} else {
			t.Errorf("daemon dry-run mutated backend: %s", name)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{name, body, "r1"}}})
	}))
	defer backend.Close()
	users := filepath.Join(dir, "users.json")
	_ = os.WriteFile(users, []byte(`{"complete":true,"issuer":"https://id.example.com","scope":"org","users":[{"id":"alice","given_name":"Alice","family_name":"Example","human":true,"active":true}]}`), 0600)
	token := filepath.Join(dir, "token")
	_ = os.WriteFile(token, []byte("test-token"), 0600)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	configuration := map[string]any{"state_file": filepath.Join(dir, "state.json"), "listen": address, "interval": "100ms", "source": map[string]any{"kind": "file", "issuer": "https://id.example.com", "scope": "org", "file": users}, "stalwart": map[string]any{"url": backend.URL, "allow_http": true, "domain": "example.com", "domain_id": "d", "token_file": token}}
	b, _ := json.Marshal(configuration)
	path := filepath.Join(dir, "config.json")
	_ = os.WriteFile(path, b, 0600)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestDaemonHelper$")
	command.Env = append(os.Environ(), "RECONCILER_DAEMON_HELPER=1", "RECONCILER_DAEMON_CONFIG="+path)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- command.Wait() }()
	finished := false
	defer func() {
		if !finished {
			_ = command.Process.Kill()
			<-stopped
		}
	}()
	client := &http.Client{Timeout: time.Second}
	ready := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		response, err := client.Get("http://" + address + "/readyz")
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("daemon did not become ready")
	}
	for _, path := range []string{"/healthz", "/metrics"} {
		response, err := client.Get("http://" + address + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal(path, response.StatusCode)
		}
		if path == "/metrics" && !strings.Contains(string(body), "reconciler_mutations_total 0") {
			t.Fatal("dry run counted mutations", string(body))
		}
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-stopped:
		finished = true
		if err != nil {
			t.Fatal(fmt.Sprintf("daemon shutdown failed: %v %s", err, output.String()))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not stop gracefully")
	}
}

func TestCLIOnceDefaultsToDryRun(t *testing.T) {
	for _, apply := range []bool{false, true} {
		t.Run(map[bool]string{false: "dry-run", true: "apply"}[apply], func(t *testing.T) {
			dir := t.TempDir()
			writes := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Calls [][]json.RawMessage `json:"methodCalls"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				var name string
				_ = json.Unmarshal(req.Calls[0][0], &name)
				var body any
				switch name {
				case "x:Domain/get":
					body = map[string]any{"list": []any{map[string]any{"id": "d", "name": "example.com"}}}
				case "x:Account/query":
					body = map[string]any{"ids": []string{}, "position": 0, "total": 0}
				case "x:Account/set":
					writes++
					body = map[string]any{"created": map[string]any{"new": map[string]any{"id": "a"}}}
				default:
					t.Errorf("unexpected method %s", name)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{name, body, "r1"}}})
			}))
			defer srv.Close()
			users := filepath.Join(dir, "users.json")
			_ = os.WriteFile(users, []byte(`{"complete":true,"issuer":"https://id.example.com","scope":"org","users":[{"id":"alice","given_name":"Alice","family_name":"Example","human":true,"active":true}]}`), 0600)
			token := filepath.Join(dir, "token")
			_ = os.WriteFile(token, []byte("test-token"), 0600)
			state := filepath.Join(dir, "state.json")
			config := map[string]any{"state_file": state, "source": map[string]any{"kind": "file", "issuer": "https://id.example.com", "scope": "org", "file": users}, "stalwart": map[string]any{"url": srv.URL, "allow_http": true, "domain": "example.com", "domain_id": "d", "token_file": token}}
			b, _ := json.Marshal(config)
			path := filepath.Join(dir, "config.json")
			_ = os.WriteFile(path, b, 0600)
			args := []string{"--config", path, "--once"}
			if apply {
				args = append(args, "--apply")
			}
			if err := run(args); err != nil {
				t.Fatal(err)
			}
			_, err := os.Stat(state)
			if apply && (writes != 1 || err != nil) {
				t.Fatal("apply did not persist creation")
			}
			if !apply && (writes != 0 || !os.IsNotExist(err)) {
				t.Fatal("dry run mutated state or API")
			}
		})
	}
}
