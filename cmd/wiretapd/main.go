// wiretapd is wiretap's ingestion daemon: it fetches traces from Langfuse,
// archives them as raw NDJSON, maps them onto ECS documents, and ships them
// to Elasticsearch. See internal/pipeline for the Fetcher and Indexer that
// do the actual work; this package is the CLI around them -- subcommands,
// flags, environment variables, logging, and signal handling.
//
// Usage:
//
//	go run ./cmd/wiretapd bootstrap   create the ES index template + alias, then exit
//	go run ./cmd/wiretapd [run]       the continuous pipeline (default subcommand)
//	go run ./cmd/wiretapd backfill    re-read the whole archive and re-index it
//	go run ./cmd/wiretapd check       connectivity/config preflight -- run this first
//
// Every subcommand accepts --log-format=json (default) or --log-format=text.
// Logs never include prompt or completion content at info level -- it
// contains this project's canary token and, in a real deployment, would
// contain user data. See run.go's logging calls: only counts, IDs, and
// durations are logged, never an event's Messages/Output.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "wiretapd: error:", err)
		os.Exit(1)
	}
}

func dispatch(args []string) error {
	sub := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}

	switch sub {
	case "bootstrap":
		return cmdBootstrap(args)
	case "run":
		return cmdRun(args)
	case "backfill":
		return cmdBackfill(args)
	case "check":
		return cmdCheck(args)
	default:
		return fmt.Errorf("unknown subcommand %q (want: bootstrap, run, backfill, check)", sub)
	}
}
