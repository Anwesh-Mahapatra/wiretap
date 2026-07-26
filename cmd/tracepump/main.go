// tracepump polls the Langfuse public API for traces and appends each one,
// exactly as the API returned it, as one line of NDJSON to a shared file for
// a Bindplane File source to tail. Langfuse has no push mechanism for
// traces, so this exists to bridge that gap.
//
// Usage: go run ./cmd/tracepump [--once]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"wiretap/internal/env"
)

const (
	defaultEnvFile     = ".env"
	defaultLangfuseURL = "http://localhost:3000"
	defaultOutPath     = "/data/langfuse-traces.ndjson"
	defaultStatePath   = "tracepump-state.json"
	defaultInterval    = 30 * time.Second

	pageLimit = 100

	// Langfuse traces are written asynchronously by the Langfuse worker, so
	// a trace can become queryable via the API slightly after its own
	// timestamp. If we only ever asked for traces strictly newer than the
	// last checkpoint, a straggler could permanently slip through the gap
	// between two polls. Instead, every poll re-queries a window that
	// overlaps the previous one by this amount, and relies on the
	// checkpoint's seen-ID set (not the timestamp filter) to avoid
	// re-emitting traces that were already written.
	overlapWindow = 5 * time.Minute

	initialBackoff = 1 * time.Second
	maxBackoff     = 5 * time.Minute
)

// tracesResponse mirrors just enough of Langfuse's GET /api/public/traces
// envelope to paginate and de-duplicate. Each element of Data is kept as raw
// JSON so it can be written out byte-for-byte, untouched.
type tracesResponse struct {
	Data []json.RawMessage `json:"data"`
	Meta struct {
		Page       int `json:"page"`
		TotalPages int `json:"totalPages"`
	} `json:"meta"`
}

// traceCore is the minimal subset of a trace's fields needed for
// pagination/dedup bookkeeping; it is never used for anything written to
// the output file.
type traceCore struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
}

type seenEntry struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
}

type checkpointState struct {
	LastTimestamp string      `json:"lastTimestamp"`
	Seen          []seenEntry `json:"seen"`
}

type config struct {
	baseURL   string
	publicKey string
	secretKey string
	outPath   string
	statePath string
}

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

	cfg := config{
		// Run from the host (e.g. via `go run ./cmd/tracepump`), so this
		// defaults to the published port on localhost. The containerized
		// service overrides this to http://langfuse-web:3000, since inside
		// that container "localhost" would mean the tracepump container
		// itself, not the langfuse-web service. See docker-compose.yml and
		// RUNBOOK.md.
		baseURL:   env.OrDefault("LANGFUSE_BASE_URL", defaultLangfuseURL),
		publicKey: publicKey,
		secretKey: secretKey,
		outPath:   env.OrDefault("TRACEPUMP_OUT", defaultOutPath),
		statePath: env.OrDefault("TRACEPUMP_STATE", defaultStatePath),
	}

	interval := defaultInterval
	if v := os.Getenv("TRACEPUMP_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("parsing TRACEPUMP_INTERVAL=%q: %w", v, err)
		}
		interval = d
	}

	cp, err := loadCheckpoint(cfg.statePath)
	if err != nil {
		return err
	}

	out, err := newNDJSONWriter(cfg.outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	httpClient := &http.Client{Timeout: 30 * time.Second}
	backoff := initialBackoff

	for {
		emitted, err := pollOnce(ctx, httpClient, cfg, cp, out)
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
		fmt.Fprintf(os.Stderr, "tracepump: poll ok, emitted %d new trace(s)\n", emitted)
		if err := saveCheckpoint(cfg.statePath, cp); err != nil {
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
	if err := saveCheckpoint(cfg.statePath, cp); err != nil {
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

// pollOnce walks every page of traces from cp's checkpoint cutoff onward,
// appending any not-yet-seen trace to out and advancing cp in place.
func pollOnce(ctx context.Context, client *http.Client, cfg config, cp *checkpointState, out *ndjsonWriter) (emitted int, err error) {
	seen := make(map[string]struct{}, len(cp.Seen))
	for _, e := range cp.Seen {
		seen[e.ID] = struct{}{}
	}

	var maxTime time.Time
	maxTimestamp := cp.LastTimestamp
	if maxTimestamp != "" {
		maxTime, _ = time.Parse(time.RFC3339Nano, maxTimestamp)
	}

	var cutoff time.Time
	if !maxTime.IsZero() {
		cutoff = maxTime.Add(-overlapWindow)
	}

	newSeen := append([]seenEntry{}, cp.Seen...)

	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return emitted, err
		}

		resp, err := fetchTracesPage(ctx, client, cfg, cutoff, page)
		if err != nil {
			return emitted, err
		}

		for _, raw := range resp.Data {
			var core traceCore
			if err := json.Unmarshal(raw, &core); err != nil {
				fmt.Fprintf(os.Stderr, "tracepump: skipping a trace with unparsable id/timestamp: %v\n", err)
				continue
			}
			if _, dup := seen[core.ID]; dup {
				continue
			}

			if err := out.WriteLine(raw); err != nil {
				return emitted, fmt.Errorf("writing trace %q: %w", core.ID, err)
			}
			emitted++
			seen[core.ID] = struct{}{}
			newSeen = append(newSeen, seenEntry{ID: core.ID, Timestamp: core.Timestamp})

			if t, perr := time.Parse(time.RFC3339Nano, core.Timestamp); perr == nil && t.After(maxTime) {
				maxTime = t
				maxTimestamp = core.Timestamp
			}
		}

		if len(resp.Data) == 0 || resp.Meta.Page >= resp.Meta.TotalPages {
			break
		}
	}

	// Prune seen entries older than the *next* poll's cutoff: the API's
	// fromTimestamp filter will exclude them from every future page anyway,
	// so keeping them around would only grow the checkpoint file forever.
	var nextCutoff time.Time
	if !maxTime.IsZero() {
		nextCutoff = maxTime.Add(-overlapWindow)
	}
	pruned := newSeen[:0]
	for _, e := range newSeen {
		t, perr := time.Parse(time.RFC3339Nano, e.Timestamp)
		if perr != nil || !t.Before(nextCutoff) {
			pruned = append(pruned, e)
		}
	}

	cp.LastTimestamp = maxTimestamp
	cp.Seen = pruned
	return emitted, nil
}

func fetchTracesPage(ctx context.Context, client *http.Client, cfg config, cutoff time.Time, page int) (*tracesResponse, error) {
	u, err := url.Parse(strings.TrimRight(cfg.baseURL, "/") + "/api/public/traces")
	if err != nil {
		return nil, fmt.Errorf("building URL: %w", err)
	}
	q := u.Query()
	q.Set("page", strconv.Itoa(page))
	q.Set("limit", strconv.Itoa(pageLimit))
	q.Set("orderBy", "timestamp.asc")
	if !cutoff.IsZero() {
		q.Set("fromTimestamp", cutoff.Format(time.RFC3339Nano))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.SetBasicAuth(cfg.publicKey, cfg.secretKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("langfuse API returned status %s: %s", resp.Status, body)
	}

	var tr tracesResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return &tr, nil
}

func loadCheckpoint(path string) (*checkpointState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &checkpointState{}, nil
		}
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	var cp checkpointState
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("parsing %q: %w", path, err)
	}
	return &cp, nil
}

// saveCheckpoint writes via a temp file plus rename so a crash mid-write
// can never corrupt or truncate the existing checkpoint.
func saveCheckpoint(path string, cp *checkpointState) error {
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding checkpoint: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("writing %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming %q to %q: %w", tmp, path, err)
	}
	return nil
}

// ndjsonWriter appends NDJSON lines to a file, always in O_APPEND mode and
// never truncating. If the file is rotated out from under it (deleted, or
// replaced -- inode changes), it transparently reopens before the next
// write, creating a fresh file if necessary.
type ndjsonWriter struct {
	path  string
	file  *os.File
	inode uint64
}

func newNDJSONWriter(path string) (*ndjsonWriter, error) {
	w := &ndjsonWriter{path: path}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *ndjsonWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening %q: %w", w.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("stat %q: %w", w.path, err)
	}
	if w.file != nil {
		w.file.Close()
	}
	w.file = f
	w.inode = inodeOf(info)
	return nil
}

func (w *ndjsonWriter) WriteLine(raw []byte) error {
	if info, err := os.Stat(w.path); err != nil || inodeOf(info) != w.inode {
		if err := w.open(); err != nil {
			return err
		}
	}
	line := append(append([]byte{}, raw...), '\n')
	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("writing to %q: %w", w.path, err)
	}
	return nil
}

func (w *ndjsonWriter) Close() error {
	if w.file == nil {
		return nil
	}
	return w.file.Close()
}

func inodeOf(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
