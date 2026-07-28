package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"wiretap/internal/esink"
	"wiretap/internal/pipeline"
)

// defaultFetchInterval matches cmd/tracepump's own default, so a fetch
// stage started by wiretapd behaves the same as one started by tracepump.
const defaultFetchInterval = 30 * time.Second

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	once := fs.Bool("once", false, "perform a single fetch+index pass and exit")
	noFetch := fs.Bool("no-fetch", false, "skip fetching -- only index what's already in the archive (use when tracepump is running as its own container)")
	batchSize := fs.Int("batch-size", 100, "bulk indexing batch size")
	flushInterval := fs.Duration("flush-interval", 10*time.Second, "how often the indexer scans the archive for new lines and flushes to elasticsearch")
	fromStr := fs.String("from", "", "only fetch traces at or after this RFC3339 timestamp (first run only; ignored once a fetch checkpoint exists, and ignored entirely with --no-fetch)")
	skipHealthchecks := fs.Bool("skip-healthchecks", true, "drop litellm-internal-health-check events before indexing -- wiretapd defaults this true, unlike tracepump, since it has an opinion about what belongs in Elasticsearch")
	dryRun := fs.Bool("dry-run", false, "map and print documents instead of indexing them -- how a mapping change gets reviewed before it touches the index")
	logFormat := fs.String("log-format", "json", "log format: json or text")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := newLogger(*logFormat)
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	var fromTime time.Time
	if *fromStr != "" {
		fromTime, err = time.Parse(time.RFC3339, *fromStr)
		if err != nil {
			return fmt.Errorf("parsing --from=%q: %w", *fromStr, err)
		}
	}

	var sink *esink.BulkIndexer
	if !*dryRun {
		sink = esink.NewBulkIndexer(cfg.esClient(), cfg.indexBase, esink.WithBatchSize(*batchSize))
	}

	ix, err := pipeline.NewIndexer(pipeline.IndexConfig{
		ArchivePath:      cfg.archivePath,
		StatePath:        cfg.indexStatePath,
		SkipHealthchecks: *skipHealthchecks,
		DryRun:           *dryRun,
		ECS:              cfg.ecsConfig(),
	}, sink, logger)
	if err != nil {
		return err
	}

	var fetcher *pipeline.Fetcher
	if !*noFetch {
		fetcher, err = pipeline.NewFetcher(cfg.langfuseClient(), pipeline.FetchConfig{
			OutPath:          cfg.archivePath,
			StatePath:        cfg.fetchStatePath,
			SkipHealthchecks: *skipHealthchecks,
			From:             fromTime,
		})
		if err != nil {
			return err
		}
		defer fetcher.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *once {
		// Sequential, not concurrent: a single index pass must see
		// whatever the single fetch pass just wrote. Racing them (as the
		// continuous path does, on purpose, since they're independent
		// there) would make --once's result depend on which stage
		// happened to finish first.
		if fetcher != nil {
			if err := runFetchOnce(ctx, fetcher, logger); err != nil {
				return err
			}
		}
		result, err := ix.ProcessNewLines(ctx)
		if err != nil {
			return fmt.Errorf("index pass: %w", err)
		}
		logIndexResult(logger, result)
	} else {
		var wg sync.WaitGroup
		if fetcher != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				runFetchLoop(ctx, fetcher, logger)
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			runIndexLoop(ctx, ix, logger, *flushInterval)
		}()
		wg.Wait()
	}

	if sink != nil {
		// ctx is already cancelled by now in the continuous path (that's
		// what stopped the loops) -- reusing it here would fail the
		// flush instantly, so this gets its own short-lived context. See
		// internal/pipeline/index.go's comment on why anything still
		// sitting in the sink at this point is safe to flush late.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := sink.Close(shutdownCtx); err != nil {
			logger.Error("final flush failed", "error", err)
		}
		logSinkCounters(logger, "final index counters", sink)
	}

	return nil
}

func runFetchOnce(ctx context.Context, f *pipeline.Fetcher, logger *slog.Logger) error {
	emitted, skipped, err := f.PollOnce(ctx)
	if err != nil {
		return fmt.Errorf("fetch pass: %w", err)
	}
	logger.Info("fetch pass ok", "emitted", emitted, "skipped", skipped)
	if err := f.SaveCheckpoint(); err != nil {
		return fmt.Errorf("saving fetch checkpoint: %w", err)
	}
	return nil
}

// runFetchLoop polls on defaultFetchInterval (matching cmd/tracepump's own
// default) with capped exponential backoff on failure, until ctx is
// cancelled.
func runFetchLoop(ctx context.Context, f *pipeline.Fetcher, logger *slog.Logger) {
	backoff := 1 * time.Second
	const maxBackoff = 5 * time.Minute

	for {
		emitted, skipped, err := f.PollOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("fetch poll failed", "error", err, "retry_in", backoff.String())
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		backoff = 1 * time.Second
		logger.Info("fetch poll ok", "emitted", emitted, "skipped", skipped)
		if err := f.SaveCheckpoint(); err != nil {
			logger.Error("fetch checkpoint save failed", "error", err)
		}

		if !sleepCtx(ctx, defaultFetchInterval) {
			return
		}
	}
}

// runIndexLoop scans the archive for new lines every interval, until ctx is
// cancelled.
func runIndexLoop(ctx context.Context, ix *pipeline.Indexer, logger *slog.Logger, interval time.Duration) {
	for {
		result, err := ix.ProcessNewLines(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("index pass failed", "error", err)
		} else {
			logIndexResult(logger, result)
		}

		if !sleepCtx(ctx, interval) {
			return
		}
	}
}

func logIndexResult(logger *slog.Logger, result pipeline.IndexResult) {
	logger.Info("index pass ok",
		"lines", result.Lines,
		"parsed", result.Parsed,
		"parse_errors", result.ParseErrors,
		"skipped", result.Skipped,
		"queued", result.Queued,
	)
}

func logSinkCounters(logger *slog.Logger, msg string, sink *esink.BulkIndexer) {
	c := sink.Counters()
	logger.Info(msg,
		"attempted", c.Attempted,
		"indexed", c.Indexed,
		"failed", c.Failed,
		"retried", c.Retried,
		"dead_lettered", c.DeadLettered,
	)
}

// sleepCtx waits for d, or returns false early if ctx is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
