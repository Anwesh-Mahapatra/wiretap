package pipeline

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"wiretap/internal/ecs"
	"wiretap/internal/esink"
	"wiretap/internal/model"
	"wiretap/internal/parse"
)

// maxLineSize caps how large one archive line is allowed to be before
// bufio.Scanner gives up -- generous relative to any real Langfuse trace,
// so it only ever triggers on a genuinely corrupt archive.
const maxLineSize = 10 * 1024 * 1024

// IndexConfig is an Indexer's configuration.
type IndexConfig struct {
	ArchivePath string
	// StatePath is the *indexer's own* checkpoint file -- deliberately
	// separate from the Fetcher's (see indexCheckpointState's doc comment
	// for why conflating them would be a data-loss bug, not just an
	// inconvenience).
	StatePath        string
	SkipHealthchecks bool
	// DryRun maps every line and prints the resulting document instead of
	// indexing it -- how a mapping change gets reviewed before it touches
	// the index.
	DryRun bool
	ECS    ecs.Config
	// Source selects which parser and mapper this indexer uses. The two
	// planes' archives hold genuinely different record shapes -- a
	// Langfuse trace and a LiteLLM spend record -- so pointing an indexer
	// at the wrong archive is a real mistake, and this is what makes it a
	// configuration choice rather than something inferred per line. The
	// zero value is SourceLangfuse, which keeps every existing caller
	// correct without change.
	Source model.Source
}

// parseAndMap turns one archive line into an indexable document using the
// pair appropriate to this indexer's source. Keeping the two pairs behind
// one call site is what lets scan stay source-agnostic: everything else in
// this file -- checkpointing, offsets, batching, dry-run -- is identical
// for both planes and should not be duplicated to serve them.
func (ix *Indexer) parseAndMap(line []byte, lineNo int) (*model.LLMEvent, *ecs.Document, error) {
	if ix.cfg.Source == model.SourceLiteLLM {
		ev, err := parse.ParseGatewayLine(line, lineNo)
		if err != nil {
			return nil, nil, err
		}
		return ev, ecs.MapGateway(ev, ix.cfg.ECS), nil
	}
	ev, err := parse.ParseLine(line, lineNo)
	if err != nil {
		return nil, nil, err
	}
	return ev, ecs.Map(ev, ix.cfg.ECS), nil
}

// indexCheckpointState is the Indexer's own persisted progress: how many
// bytes (and, for error messages, which line number) of the archive have
// already been read and queued for indexing.
//
// This is a second, independent checkpoint from the Fetcher's
// (fetchCheckpointState) on purpose. The Fetcher's checkpoint answers "what
// have I pulled from Langfuse"; this one answers "what have I shipped
// toward Elasticsearch." Conflating them into one checkpoint would mean an
// Elasticsearch outage -- which stalls this checkpoint but not the
// Fetcher's -- either blocks fetching too (needless, and Langfuse's own
// retention becomes the deadline) or, worse, the fetcher's progress
// silently stands in for the indexer's and an outage causes permanent data
// loss: traces the Fetcher marked "seen" and moved past, that the Indexer
// never actually got to ship.
type indexCheckpointState struct {
	Offset int64 `json:"offset"`
	Line   int   `json:"line"`
}

// IndexResult summarises one Indexer run (ProcessNewLines or Backfill).
type IndexResult struct {
	Lines       int // lines read from the archive
	Parsed      int // lines that parsed into a model.LLMEvent
	ParseErrors int // lines that didn't (logged, not fatal -- see run)
	Skipped     int // health-check events dropped per SkipHealthchecks
	Queued      int // events mapped and handed to the sink (or printed, in DryRun)
}

// Indexer tails the NDJSON archive tracepump/the Fetcher writes, parsing
// (internal/parse) and mapping (internal/ecs) each new line, then handing
// the result to a sink (internal/esink.BulkIndexer) -- or, in DryRun mode,
// printing it instead of indexing anything.
type Indexer struct {
	cfg    IndexConfig
	sink   *esink.BulkIndexer // nil when cfg.DryRun
	cp     *indexCheckpointState
	logger *slog.Logger
}

// NewIndexer loads (or initializes) the indexer checkpoint named in
// cfg.StatePath. sink may be nil only if cfg.DryRun is true.
func NewIndexer(cfg IndexConfig, sink *esink.BulkIndexer, logger *slog.Logger) (*Indexer, error) {
	if !cfg.DryRun && sink == nil {
		return nil, fmt.Errorf("pipeline: NewIndexer requires a non-nil sink unless DryRun is set")
	}
	cp, err := loadIndexCheckpoint(cfg.StatePath)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Indexer{cfg: cfg, sink: sink, cp: cp, logger: logger}, nil
}

// ProcessNewLines reads and indexes whatever's been appended to the
// archive since the last checkpoint, then persists the new checkpoint.
// This is what cmd/wiretapd's "run" subcommand calls on each tick.
func (ix *Indexer) ProcessNewLines(ctx context.Context) (IndexResult, error) {
	return ix.scan(ctx, ix.cp.Offset, ix.cp.Line, true)
}

// Backfill re-reads the *entire* archive from the start and re-indexes
// everything, ignoring (and not advancing) the checkpoint. This is the
// reason the archive is kept as a durable, replayable file rather than
// being consumed and discarded: after fixing a mapping bug, Backfill is how
// every already-fetched trace gets reprocessed through the fix. Safe to run
// at any time because indexing is _id-keyed and therefore idempotent --
// re-indexing something already in Elasticsearch overwrites it with
// (hopefully identical, post-fix possibly corrected) data rather than
// duplicating it.
func (ix *Indexer) Backfill(ctx context.Context) (IndexResult, error) {
	return ix.scan(ctx, 0, 0, false)
}

func (ix *Indexer) scan(ctx context.Context, startOffset int64, startLine int, persist bool) (IndexResult, error) {
	var result IndexResult

	f, err := os.Open(ix.cfg.ArchivePath)
	if err != nil {
		return result, fmt.Errorf("opening archive %q: %w", ix.cfg.ArchivePath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return result, fmt.Errorf("stat archive %q: %w", ix.cfg.ArchivePath, err)
	}
	if startOffset > info.Size() {
		// The archive is smaller than our last checkpoint -- it was
		// replaced (see RUNBOOK.md's reset procedure). Restart from the
		// top rather than seeking past EOF.
		startOffset = 0
		startLine = 0
	}
	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		return result, fmt.Errorf("seeking archive %q: %w", ix.cfg.ArchivePath, err)
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	offset := startOffset
	lineNo := startLine

	for scanner.Scan() {
		if ctx.Err() != nil {
			// Stop reading more, but still fall through to flush/persist
			// whatever was already queued -- see the comment below on
			// why that's safe even if the flush itself then fails.
			break
		}

		line := scanner.Bytes()
		lineNo++
		offset += int64(len(line)) + 1 // +1 for the newline bufio.Scanner strips
		result.Lines++

		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		ev, doc, perr := ix.parseAndMap(line, lineNo)
		if perr != nil {
			result.ParseErrors++
			ix.logger.Error("skipping unparsable archive line", "line", lineNo, "error", perr)
			continue
		}
		result.Parsed++

		if ix.cfg.SkipHealthchecks && ev.IsHealthCheck {
			result.Skipped++
			continue
		}

		// An event with no identifier cannot be indexed idempotently:
		// Elasticsearch would auto-generate an _id, making every replay
		// create a fresh duplicate. Skip rather than corrupt the
		// backfill guarantee. See model.LLMEvent.DocumentID.
		docID := ev.DocumentID()
		if docID == "" {
			result.Skipped++
			ix.logger.Warn("skipping archive line with no document id", "line", lineNo)
			continue
		}

		if ix.cfg.DryRun {
			pretty, _ := json.MarshalIndent(doc, "", "  ")
			fmt.Println(string(pretty))
			result.Queued++
			continue
		}

		// _id comes from the event, not from a field this stage picks:
		// the two planes need different rules and getting it wrong
		// collapses retried gateway attempts onto one document. See
		// model.LLMEvent.DocumentID.
		if err := ix.sink.Add(ctx, docID, doc); err != nil {
			return result, fmt.Errorf("queuing trace %q for indexing: %w", ev.TraceID, err)
		}
		result.Queued++
	}
	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("reading archive %q: %w", ix.cfg.ArchivePath, err)
	}

	if !ix.cfg.DryRun && ix.sink != nil {
		if err := ix.sink.Flush(ctx); err != nil {
			// Deliberately not persisting the checkpoint below when this
			// happens: anything already handed to the sink this scan is
			// still sitting in its in-memory batch (or was requeued there
			// on a cancelled retry -- see esink.BulkIndexer.sendWithRetry)
			// and will be retried on the *next* successful Flush, whether
			// that's the next tick or the final shutdown flush. Not
			// advancing the checkpoint here just means the next
			// ProcessNewLines call re-reads and re-Adds the same lines --
			// harmless, since indexing is _id-idempotent, and safer than
			// advancing past data we don't yet know reached Elasticsearch.
			return result, fmt.Errorf("flushing to elasticsearch: %w", err)
		}
	}

	if persist {
		ix.cp.Offset = offset
		ix.cp.Line = lineNo
		if err := ix.saveCheckpoint(); err != nil {
			return result, fmt.Errorf("saving indexer checkpoint: %w", err)
		}
	}

	return result, nil
}

func (ix *Indexer) saveCheckpoint() error {
	return atomicWriteJSON(ix.cfg.StatePath, ix.cp)
}

func loadIndexCheckpoint(path string) (*indexCheckpointState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &indexCheckpointState{}, nil
		}
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	var cp indexCheckpointState
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("parsing %q: %w", path, err)
	}
	return &cp, nil
}
