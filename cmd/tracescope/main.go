// tracescope fetches a single Langfuse trace via the public API and prints a
// flattened, human-readable view of it.
//
// Usage: go run ./cmd/tracescope <traceId>
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"wiretap/internal/env"
	"wiretap/internal/langfuse"
)

const (
	defaultEnvFile     = ".env"
	defaultLangfuseURL = "http://localhost:3000"
	requestTimeout     = 15 * time.Second
)

func printJSONField(label string, v any) {
	if v == nil {
		fmt.Printf("%s: (none)\n", label)
		return
	}
	b, err := json.MarshalIndent(v, "    ", "  ")
	if err != nil {
		fmt.Printf("%s: %v\n", label, v)
		return
	}
	fmt.Printf("%s:\n    %s\n", label, b)
}

// outcomeTags are wiretap's mutually-exclusive scenario labels (see
// scenarios.json). A single chat-completion request produces exactly one of
// these; a trace carrying more than one has had requests merged into it.
var outcomeTags = []string{"benign", "injection", "truncated"}

// warnIfMerged prints a loud warning if t shows symptoms of the
// id-equals-session-id merged-trace bug (see notes.md): LiteLLM falling
// back to session_id as the trace ID whenever a caller doesn't set an
// explicit trace_id. A merged trace pairs input from one request with
// output from another, so its input/output correlation, tags, and latency
// cannot be trusted for anything -- including detection rules.
func warnIfMerged(t *langfuse.Trace) {
	if t.ID == t.SessionID {
		fmt.Printf("WARNING: trace id equals session id (%q). This trace is a merged\n", t.ID)
		fmt.Println("  artifact, not a single request: LiteLLM fell back to session_id as the")
		fmt.Println("  trace ID, so observations from every request sharing this session may have")
		fmt.Println("  been written into it. Its input/output pairing cannot be trusted -- the")
		fmt.Println("  input shown below may belong to a different request than the output.")
		fmt.Println()
	}

	var found []string
	for _, outcome := range outcomeTags {
		for _, tag := range t.Tags {
			if tag == outcome {
				found = append(found, outcome)
				break
			}
		}
	}
	if len(found) > 1 {
		fmt.Printf("WARNING: trace carries %d mutually-exclusive outcome tags (%s).\n", len(found), strings.Join(found, ", "))
		fmt.Println("  A single request produces exactly one of benign/injection/truncated, so")
		fmt.Println("  this trace has accumulated tags from more than one request. Its tags")
		fmt.Println("  cannot be used to identify which scenario produced the input/output below.")
		fmt.Println()
	}
}

func printTrace(t *langfuse.Trace) {
	fmt.Printf("trace id:   %s\n", t.ID)
	fmt.Printf("name:       %s\n", t.Name)
	fmt.Printf("userId:     %s\n", t.UserID)
	fmt.Printf("sessionId:  %s\n", t.SessionID)
	fmt.Printf("tags:       %s\n", strings.Join(t.Tags, ", "))
	fmt.Println()

	warnIfMerged(t)

	generations := 0
	for _, obs := range t.Observations {
		if obs.Type != "GENERATION" {
			continue
		}
		generations++

		fmt.Printf("--- generation: %s ---\n", obs.Name)
		fmt.Printf("model:              %s\n", obs.Model)
		fmt.Printf("latency (s):        %.3f\n", obs.Latency)
		if obs.Usage != nil {
			fmt.Printf("prompt tokens:      %d\n", obs.Usage.Input)
			fmt.Printf("completion tokens:  %d\n", obs.Usage.Output)
		} else {
			fmt.Printf("prompt tokens:      (none)\n")
			fmt.Printf("completion tokens:  (none)\n")
		}
		printJSONField("input", obs.Input)
		printJSONField("output", obs.Output)
		fmt.Println()
	}

	if generations == 0 {
		fmt.Println("(no generations found on this trace)")
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/tracescope <traceId>")
		os.Exit(1)
	}
	traceID := os.Args[1]

	if err := run(traceID); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(traceID string) error {
	if err := env.LoadDotEnv(defaultEnvFile); err != nil {
		return err
	}

	publicKey := os.Getenv("LANGFUSE_PUBLIC_KEY")
	secretKey := os.Getenv("LANGFUSE_SECRET_KEY")
	if publicKey == "" || secretKey == "" {
		return fmt.Errorf("LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY must be set (in the environment or .env)")
	}
	// Run from the host, so this points at the published port, unlike the
	// tracepump container which must use http://langfuse-web:3000 instead
	// (see docker-compose.yml and RUNBOOK.md) since "localhost" inside that
	// container would mean the container itself, not the langfuse-web
	// service.
	baseURL := env.OrDefault("LANGFUSE_BASE_URL", defaultLangfuseURL)

	client := langfuse.New(baseURL, publicKey, secretKey, langfuse.WithUserAgent("wiretap-tracescope"))

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	trace, err := client.GetTrace(ctx, traceID)
	if err != nil {
		if langfuse.IsNotFound(err) {
			return fmt.Errorf("no trace with id %q", traceID)
		}
		return err
	}

	printTrace(trace)
	return nil
}
