// tracepump polls the Langfuse public API for traces and appends each one,
// byte-for-byte and unmodified, as one line of NDJSON to a shared file for
// wiretapd's indexer to tail. Langfuse has no push mechanism for traces, so
// this exists to bridge that gap.
//
// tracepump is deliberately a faithful pipe, not a transform: normalizing
// Langfuse's shape into anything else (ECS or otherwise) is internal/ecs's
// job, run by wiretapd against this archive. Keeping the archive raw means
// a mapping bug can always be fixed and replayed without re-fetching from
// Langfuse.
//
// The actual polling/checkpoint/archive-writing mechanics live in
// internal/pipeline.Fetcher -- this file is just that plus a CLI: flags,
// env vars, the poll loop's cadence and logging, and signal handling.
// cmd/wiretapd's own fetch stage (unless run with --no-fetch) uses the
// exact same Fetcher type, not a reimplementation of it.
//
// Usage: go run ./cmd/tracepump [--once]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"wiretap/internal/env"
	"wiretap/internal/langfuse"
	"wiretap/internal/pipeline"
)

const (
	defaultEnvFile     = ".env"
	defaultLangfuseURL = "http://localhost:3000"
	defaultOutPath     = "/data/langfuse-traces.ndjson"
	defaultStatePath   = "tracepump-state.json"
	defaultInterval    = 30 * time.Second

	initialBackoff = 1 * time.Second
	maxBackoff     = 5 * time.Minute
)

func main() {
	once := flag.Bool("once", false, "perform a single poll pass and exit, instead of polling continuously")
	flag.Parse()

	if err := run(*once); err != nil {
		fmt.Fprintln(os.Stderr, "tracepump: error:", err)
		os.Exit(1)
	}
}

func run(once bool) error {
	if err := env.LoadDotEnv(defaultEnvFile); err != nil {
		return err
	}

	publicKey := os.Getenv("LANGFUSE_PUBLIC_KEY")
	secretKey := os.Getenv("LANGFUSE_SECRET_KEY")
	if publicKey == "" || secretKey == "" {
		return fmt.Errorf("LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY must be set (in the environment or .env)")
	}

	// Run from the host (e.g. via `go run ./cmd/tracepump`), so this
	// defaults to the published port on localhost. The containerized
	// service overrides this to http://langfuse-web:3000, since inside
	// that container "localhost" would mean the tracepump container
	// itself, not the langfuse-web service. See docker-compose.yml and
	// RUNBOOK.md.
	baseURL := env.OrDefault("LANGFUSE_BASE_URL", defaultLangfuseURL)

	cfg := pipeline.FetchConfig{
		OutPath:   env.OrDefault("TRACEPUMP_OUT", defaultOutPath),
		StatePath: env.OrDefault("TRACEPUMP_STATE", defaultStatePath),
	}

	interval := defaultInterval
	if v := os.Getenv("TRACEPUMP_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("parsing TRACEPUMP_INTERVAL=%q: %w", v, err)
		}
		interval = d
	}

	if v := os.Getenv("TRACEPUMP_SKIP_HEALTHCHECKS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("parsing TRACEPUMP_SKIP_HEALTHCHECKS=%q: %w", v, err)
		}
		cfg.SkipHealthchecks = b
	}

	client := langfuse.New(baseURL, publicKey, secretKey, langfuse.WithUserAgent("wiretap-tracepump"))
	fetcher, err := pipeline.NewFetcher(client, cfg)
	if err != nil {
		return err
	}
	defer fetcher.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	backoff := initialBackoff

	for {
		emitted, skipped, err := fetcher.PollOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break // shutting down
			}
			if once {
				return fmt.Errorf("poll: %w", err)
			}
			fmt.Fprintf(os.Stderr, "tracepump: poll failed: %v (retrying in %s)\n", err, backoff)
			if !sleep(ctx, backoff) {
				break // interrupted while backing off
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		backoff = initialBackoff
		fmt.Fprintf(os.Stderr, "tracepump: poll ok, emitted %d new trace(s), skipped %d health-check(s)\n", emitted, skipped)
		if err := fetcher.SaveCheckpoint(); err != nil {
			fmt.Fprintf(os.Stderr, "tracepump: checkpoint save failed: %v\n", err)
		}

		if once {
			return nil
		}

		if !sleep(ctx, interval) {
			break // interrupted while waiting for the next poll
		}
	}

	// Reached only via SIGINT/SIGTERM. Persist a final checkpoint before
	// exiting so a restart resumes from here rather than re-polling
	// everything already emitted.
	if err := fetcher.SaveCheckpoint(); err != nil {
		return fmt.Errorf("final checkpoint: %w", err)
	}
	return nil
}

// sleep waits for d, or returns false early if ctx is cancelled first.
func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
