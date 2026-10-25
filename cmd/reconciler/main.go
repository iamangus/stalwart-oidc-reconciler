package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/iamangus/stalwart-oidc-reconciler/internal/config"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/httpapi"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/identity"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/reconcile"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/server"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/source"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/stalwart"
	"github.com/iamangus/stalwart-oidc-reconciler/internal/state"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("reconciler stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("reconciler", flag.ContinueOnError)
	path := flags.String("config", "/etc/reconciler/config.json", "configuration file")
	once := flags.Bool("once", false, "plan/reconcile once, then exit")
	apply := flags.Bool("apply", false, "enable mutations (default: dry-run)")
	showVersion := flags.Bool("version", false, "print version")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	store, err := state.Open(c.StateFile)
	if err != nil {
		return err
	}
	defer store.Close()
	// Validate state before making any API request, including in dry-run mode.
	initial, err := store.Load()
	if err != nil {
		return err
	}
	if initial.Fingerprint != "" && initial.Fingerprint != c.ReconcilePolicy().Fingerprint() {
		return errors.New("configuration scope does not match existing state")
	}
	var src identity.Source
	if c.Source.Kind == "zitadel" {
		src = &source.Zitadel{API: httpapi.New(c.Source.URL, c.Source.TokenFile, config.Duration(c.HTTPTimeout)),
			Issuer: c.Source.Issuer, Organization: c.Source.Scope, PageSize: c.Source.PageSize, MaxUsers: c.Policy.MaxUsers}
	} else {
		src = source.File{Path: c.Source.File}
	}
	target := &stalwart.Client{API: httpapi.New(c.Stalwart.URL, c.Stalwart.TokenFile, config.Duration(c.HTTPTimeout)),
		JMAPPath: c.Stalwart.JMAPPath, MaxAccounts: c.Stalwart.MaxAccounts,
		Domain: c.Stalwart.Domain, DomainID: c.Stalwart.DomainID}
	engine := reconcile.Engine{Source: src, Target: target, Store: store, Policy: c.ReconcilePolicy()}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *once {
		cycle, cancel := context.WithTimeout(ctx, config.Duration(c.CycleTimeout))
		defer cancel()
		plan, err := engine.Run(cycle, *apply)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(plan)
	}
	var lastSuccess atomic.Int64
	var cycles, failures, mutations atomic.Uint64
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		last := lastSuccess.Load()
		if last == 0 || time.Since(time.Unix(last, 0)) > config.Duration(c.Claims.MaxStale) {
			http.Error(w, "directory not reconciled recently", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# TYPE reconciler_cycles_total counter\nreconciler_cycles_total %d\n# TYPE reconciler_errors_total counter\nreconciler_errors_total %d\n# TYPE reconciler_mutations_total counter\nreconciler_mutations_total %d\n# TYPE reconciler_last_success_timestamp_seconds gauge\nreconciler_last_success_timestamp_seconds %d\n", cycles.Load(), failures.Load(), mutations.Load(), lastSuccess.Load())
	})
	if c.Claims.Enabled {
		mux.Handle("/hooks/zitadel/claims", server.Claims{StateFile: c.StateFile,
			Fingerprint: c.ReconcilePolicy().Fingerprint(), Scope: c.Source.Scope, KeyFile: c.Claims.SigningKeyFile,
			ClientIDs: c.Claims.ClientIDs, ClaimName: c.Claims.ClaimName, MaxStale: config.Duration(c.Claims.MaxStale), Apply: *apply})
	}
	srv := &http.Server{Addr: c.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	serverErrors := make(chan error, 1)
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return errors.New("cannot bind HTTP listener")
	}
	go func() { serverErrors <- srv.Serve(listener) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	slog.Info("reconciler started", "version", version, "apply", *apply, "source", c.Source.Kind)
	for {
		cycle, cancel := context.WithTimeout(ctx, config.Duration(c.CycleTimeout))
		plan, err := engine.Run(cycle, *apply)
		cancel()
		cycles.Add(1)
		if *apply {
			mutations.Add(uint64(plan.Applied))
		}
		if err != nil {
			failures.Add(1)
			slog.Error("reconciliation failed; will retry next cycle", "error", err)
		} else {
			lastSuccess.Store(time.Now().Unix())
			slog.Info("reconciliation complete", "apply", *apply, "eligible_users", plan.Users, "actions", len(plan.Actions))
		}
		timer := time.NewTimer(config.Duration(c.Interval))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case err := <-serverErrors:
			timer.Stop()
			if !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		case <-timer.C:
		}
	}
}
