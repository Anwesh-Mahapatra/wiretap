// Package pipeline is the orchestration layer connecting the pieces built
// in internal/langfuse, internal/parse, internal/ecs, and internal/esink
// into the two stages cmd/wiretapd runs: a Fetcher that pulls from Langfuse
// into the NDJSON archive, and an Indexer that tails that archive into
// Elasticsearch. See cmd/wiretapd's package doc for why they're two
// separate stages with two separate checkpoints instead of one pipeline
// with one.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"wiretap/internal/langfuse"
)

const (
	// overlapWindow re-queries a window behind the last-seen timestamp on
	// every poll, since Langfuse traces are written asynchronously and a
	// straggler could otherwise permanently slip through the gap between
	// two polls. The checkpoint's seen-ID set, not the timestamp filter
	// alone, is what actually prevents re-emitting something already
	// written.
	overlapWindow = 5 * time.Minute

	pageLimit = 100

	// healthCheckTag marks the traffic LiteLLM generates for its own model
	// health checks: on a Langfuse trace, empty input.messages and null
	// userId/sessionId; on a LiteLLM spend row, null spend_logs_metadata
	// and so no join key at all. Real, not synthetic -- these requests
	// reach the provider and cost money -- but noise for anything
	// computing per-user, per-session or per-key baselines downstream, and
	// on the gateway plane a permanent floor under join health's
	// without-join-key count.
	//
	// One constant, both fetchers, but not the same test. LiteLLM stamps
	// this literal onto a health check twice: as a request tag, which is
	// all a Langfuse trace carries and is therefore what the content
	// fetcher matches, and as the identity of the service account it
	// bills, which is the only one of the two a caller cannot forge and is
	// therefore all the gateway fetcher matches. See
	// gatewayRecordCore.isHealthCheck.
	healthCheckTag = "litellm-internal-health-check"
)

// FetchConfig is a Fetcher's configuration: where it writes the archive and
// its own checkpoint, and whether to drop LiteLLM's internal health-check
// traces before they ever reach the archive.
type FetchConfig struct {
	OutPath          string
	StatePath        string
	SkipHealthchecks bool
	// From seeds the checkpoint's cutoff timestamp, but only when the
	// checkpoint is otherwise empty (a checkpoint that already has a
	// LastTimestamp -- from any prior run -- always wins). Lets a first
	// run start from a specific point in Langfuse's history instead of
	// its earliest trace.
	From time.Time
	// Enrich, when true, fetches full trace detail (GetTraceRaw) for every
	// new trace and archives that instead of the list-shaped record --
	// see PollOnce's doc comment and internal/pipeline/enrich.go for why
	// and how. Off in the zero value, matching cmd/tracepump's default
	// (a deliberately dumb, cheap, faithful pipe); cmd/wiretapd turns it
	// on by default itself.
	Enrich bool
	// EnrichConcurrency bounds how many GetTrace calls run at once when
	// Enrich is true. Defaults to 4 (see defaultEnrichConcurrency) if left
	// at zero.
	EnrichConcurrency int
}

// fetchSeenEntry and fetchCheckpointState are the Fetcher's own persisted
// state: which trace IDs (within the overlap window) have already been
// written, and the newest timestamp seen so far.
type fetchSeenEntry struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
}

type fetchCheckpointState struct {
	LastTimestamp string           `json:"lastTimestamp"`
	Seen          []fetchSeenEntry `json:"seen"`
}

// traceCore is the minimal subset of a trace's fields the Fetcher needs for
// dedup bookkeeping and the opt-in health-check filter. It is never used
// for anything written to the archive, which always writes the original
// json.RawMessage untouched.
type traceCore struct {
	ID        string   `json:"id"`
	Timestamp string   `json:"timestamp"`
	Tags      []string `json:"tags"`
}

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// Fetcher polls Langfuse for traces and appends each one, byte-for-byte, as
// one line of NDJSON to an archive file. This is the same mechanism
// cmd/tracepump has always used (see its package doc) -- extracted here so
// cmd/wiretapd's own fetch stage is the same code, not a reimplementation
// of it, when it isn't running with --no-fetch against tracepump's own
// container instead.
//
// When cfg.Enrich is set, "byte-for-byte" still holds -- it just means
// byte-for-byte faithful to a *different, richer* API response
// (GetTraceRaw's detail payload instead of ListTraces' list-shaped one),
// fetched and archived instead of the original, never rewritten after the
// fact. See internal/pipeline/enrich.go for the concurrency-bounded,
// per-trace-failure-isolated mechanics.
type Fetcher struct {
	client *langfuse.Client
	cfg    FetchConfig
	cp     *fetchCheckpointState
	out    *ndjsonWriter

	enrichAttempted atomic.Int64
	enrichSucceeded atomic.Int64
	enrichSkipped   atomic.Int64
	enrichFailed    atomic.Int64
}

// NewFetcher opens (creating if necessary) the archive and checkpoint files
// named in cfg, ready to poll.
func NewFetcher(client *langfuse.Client, cfg FetchConfig) (*Fetcher, error) {
	cp, err := loadFetchCheckpoint(cfg.StatePath)
	if err != nil {
		return nil, err
	}
	if cp.LastTimestamp == "" && !cfg.From.IsZero() {
		cp.LastTimestamp = cfg.From.Format(time.RFC3339Nano)
	}
	out, err := newNDJSONWriter(cfg.OutPath)
	if err != nil {
		return nil, err
	}
	return &Fetcher{client: client, cfg: cfg, cp: cp, out: out}, nil
}

// Close closes the archive file. It does not save the checkpoint --
// callers must call SaveCheckpoint explicitly, since the right moment to
// persist it (after a successful poll, or during graceful shutdown) is a
// judgment call that belongs to the caller's loop, not to Close.
func (f *Fetcher) Close() error {
	return f.out.Close()
}

// SaveCheckpoint persists the Fetcher's current checkpoint to disk.
func (f *Fetcher) SaveCheckpoint() error {
	return saveFetchCheckpoint(f.cfg.StatePath, f.cp)
}

// PollOnce walks every page of traces from the checkpoint's cutoff onward,
// appending any not-yet-seen trace to the archive and advancing the
// checkpoint in memory (call SaveCheckpoint to persist it).
func (f *Fetcher) PollOnce(ctx context.Context) (emitted, skipped int, err error) {
	seen := make(map[string]struct{}, len(f.cp.Seen))
	for _, e := range f.cp.Seen {
		seen[e.ID] = struct{}{}
	}

	var maxTime time.Time
	maxTimestamp := f.cp.LastTimestamp
	if maxTimestamp != "" {
		maxTime, _ = time.Parse(time.RFC3339Nano, maxTimestamp)
	}

	var cutoff time.Time
	if !maxTime.IsZero() {
		cutoff = maxTime.Add(-overlapWindow)
	}

	newSeen := append([]fetchSeenEntry{}, f.cp.Seen...)

	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return emitted, skipped, err
		}

		resp, err := f.client.ListTraces(ctx, langfuse.ListTracesParams{
			Page:          page,
			Limit:         pageLimit,
			OrderBy:       "timestamp.asc",
			FromTimestamp: cutoff,
		})
		if err != nil {
			return emitted, skipped, err
		}

		// First pass: dedup and the health-check filter, both permanent
		// per-trace decisions that always mark a trace seen regardless of
		// enrichment. Everything left is a genuine candidate to archive.
		var candidates []traceCore
		rawByID := make(map[string]json.RawMessage, len(resp.Data))
		for _, raw := range resp.Data {
			var core traceCore
			if err := json.Unmarshal(raw, &core); err != nil {
				fmt.Fprintf(os.Stderr, "pipeline: skipping a trace with unparsable id/timestamp: %v\n", err)
				continue
			}
			if _, dup := seen[core.ID]; dup {
				continue
			}

			if f.cfg.SkipHealthchecks && hasTag(core.Tags, healthCheckTag) {
				skipped++
				seen[core.ID] = struct{}{}
				newSeen = append(newSeen, fetchSeenEntry{ID: core.ID, Timestamp: core.Timestamp})
				if t, perr := time.Parse(time.RFC3339Nano, core.Timestamp); perr == nil && t.After(maxTime) {
					maxTime = t
					maxTimestamp = core.Timestamp
				}
				continue
			}

			candidates = append(candidates, core)
			rawByID[core.ID] = raw
		}

		// Second pass: archive each candidate, enriched if configured.
		// enrichPage returns one result per candidate, in order, even for
		// the ones it skips -- see enrichTrace's doc comment for what
		// "skip" means and why it's not the same as "fail."
		var results []enrichedResult
		if f.cfg.Enrich && len(candidates) > 0 {
			results, err = f.enrichPage(ctx, candidates)
			if err != nil {
				// A systemic (non-skip) enrichment failure: nothing from
				// this page is written and the checkpoint is left exactly
				// where it was, the same way a ListTraces failure above
				// already aborts without partial progress.
				return emitted, skipped, fmt.Errorf("enrichment: %w", err)
			}
		} else {
			results = make([]enrichedResult, len(candidates))
			for i, core := range candidates {
				results[i] = enrichedResult{core: core, raw: rawByID[core.ID]}
			}
		}

		for _, r := range results {
			if r.skip {
				// Deliberately not marked seen and not advancing
				// maxTime past this ID: the existing overlap-window
				// mechanism (see overlapWindow above) will naturally
				// re-offer it on a future poll.
				continue
			}

			if err := f.out.WriteLine(r.raw); err != nil {
				return emitted, skipped, fmt.Errorf("writing trace %q: %w", r.core.ID, err)
			}
			emitted++

			seen[r.core.ID] = struct{}{}
			newSeen = append(newSeen, fetchSeenEntry{ID: r.core.ID, Timestamp: r.core.Timestamp})

			if t, perr := time.Parse(time.RFC3339Nano, r.core.Timestamp); perr == nil && t.After(maxTime) {
				maxTime = t
				maxTimestamp = r.core.Timestamp
			}
		}

		if len(resp.Data) == 0 || resp.Page >= resp.TotalPages {
			break
		}
	}

	// Prune seen entries older than the *next* poll's cutoff: the API's
	// fromTimestamp filter will exclude them from every future page
	// anyway, so keeping them around would only grow the checkpoint file
	// forever.
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

	f.cp.LastTimestamp = maxTimestamp
	f.cp.Seen = pruned
	return emitted, skipped, nil
}

func loadFetchCheckpoint(path string) (*fetchCheckpointState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &fetchCheckpointState{}, nil
		}
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	var cp fetchCheckpointState
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("parsing %q: %w", path, err)
	}
	return &cp, nil
}

// loadJSONIfExists decodes path into v, treating a missing file as an
// empty value rather than an error -- a checkpoint that has never been
// written is the normal first-run state, not a failure. Shared by every
// checkpoint loader so "absent means empty" is decided once.
func loadJSONIfExists(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading %q: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parsing %q: %w", path, err)
	}
	return nil
}

// saveFetchCheckpoint writes via a temp file plus rename so a crash
// mid-write can never corrupt or truncate the existing checkpoint.
func saveFetchCheckpoint(path string, cp *fetchCheckpointState) error {
	return atomicWriteJSON(path, cp)
}

// atomicWriteJSON is shared by both the Fetcher's and Indexer's
// checkpoints: encode as indented JSON, write to a temp file, then rename
// over the real path, so a crash mid-write never corrupts or truncates
// whatever checkpoint was already on disk.
func atomicWriteJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %q: %w", path, err)
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
