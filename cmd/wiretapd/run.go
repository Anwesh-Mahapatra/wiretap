package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"wiretap/internal/esink"
	"wiretap/internal/model"
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
	noEnrich := fs.Bool("no-enrich", false, "archive the raw list-shaped record instead of fetching full trace detail per new trace. Enrichment is on by default: it's what populates gen_ai.usage.*, gen_ai.request.model, gen_ai.response.model, and gen_ai.request.max_tokens (see internal/pipeline/enrich.go) -- with --no-enrich those fields stay permanently absent, same as before enrichment existed. Costs one extra bounded-concurrency Langfuse API call per new trace; turn it off only if that cost is the problem.")
	logFormat := fs.String("log-format", "json", "log format: json or text")
	sources := fs.String("sources", "langfuse,litellm", "comma-separated sources to run: langfuse (content plane), litellm (gateway plane), or both")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := newLogger(*logFormat)
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	// Fail at startup rather than silently sharing a file. See
	// config.validatePathIsolation.
	if err := cfg.validatePathIsolation(); err != nil {
		return err
	}

	sel, err := parseSources(*sources)
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// One plane per element. Each carries its own fetcher, indexer, sink,
	// archive and two checkpoints -- nothing is shared, which is what
	// makes "one source failing must not stop the other" a structural
	// property rather than a hope. See arch.md.
	var planes []*plane
	if sel.langfuse {
		pl, err := newContentPlane(cfg, *batchSize, *skipHealthchecks, *dryRun, *noFetch, *noEnrich, fromTime)
		if err != nil {
			return fmt.Errorf("content plane: %w", err)
		}
		planes = append(planes, pl)
	}
	if sel.litellm {
		pl, err := newGatewayPlane(cfg, *batchSize, *dryRun, *noFetch, fromTime)
		if err != nil {
			return fmt.Errorf("gateway plane: %w", err)
		}
		planes = append(planes, pl)
	}
	if len(planes) == 0 {
		return fmt.Errorf("--sources selected nothing to run")
	}
	for _, pl := range planes {
		defer pl.Close()
	}
	logger.Info("starting", "sources", sel.String(), "planes", len(planes))

	if *once {
		// Sequential, not concurrent: a single index pass must see
		// whatever the single fetch pass just wrote. Racing them (as the
		// continuous path does, on purpose, since they're independent
		// there) would make --once's result depend on which stage
		// happened to finish first.
		//
		// Planes are still independent of each other: one failing is
		// reported and the rest still run, matching the continuous path's
		// behaviour rather than diverging from it under --once.
		var errs []error
		for _, pl := range planes {
			if err := pl.RunOnce(ctx, logger); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", pl.name, err))
			}
		}
		if err := errors.Join(errs...); err != nil {
			return err
		}
	} else {
		var wg sync.WaitGroup
		for _, pl := range planes {
			pl := pl
			if pl.fetcher != nil {
				wg.Add(1)
				go func() {
					defer wg.Done()
					pl.fetcher.RunLoop(ctx, logger, pl.name)
				}()
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				runIndexLoop(ctx, pl.indexer, logger, pl.name, *flushInterval)
			}()
		}

		// Join health runs only when both planes are ingesting: with one
		// source running, every event is unmatched for a reason that has
		// nothing to do with the join, and reporting that as a rate would
		// train whoever reads it to ignore the number.
		if sel.langfuse && sel.litellm && !*dryRun {
			jh, err := newJoinHealthReporter(cfg, *flushInterval)
			if err != nil {
				logger.Error("join health disabled", "error", err)
			} else {
				wg.Add(1)
				go func() {
					defer wg.Done()
					runJoinHealthLoop(ctx, jh, logger)
				}()
			}
		}
		wg.Wait()
	}

	for _, pl := range planes {
		pl.FinalFlush(logger)
	}
	return nil
}

// plane is one source's complete, self-contained pipeline.
type plane struct {
	name    string
	fetcher poller
	indexer *pipeline.Indexer
	sink    *esink.BulkIndexer
}

// poller is what the two fetcher types have in common. They are separate
// concrete types because they talk to different APIs with different
// pagination and different checkpoints; this interface exists only so the
// loop that drives them is written once.
type poller interface {
	PollOnce(ctx context.Context) (emitted, skipped int, err error)
	SaveCheckpoint() error
	Close() error
	RunLoop(ctx context.Context, logger *slog.Logger, name string)
	LogExtraCounters(logger *slog.Logger, name string)
}

func (p *plane) Close() {
	if p.fetcher != nil {
		p.fetcher.Close()
	}
}

func (p *plane) RunOnce(ctx context.Context, logger *slog.Logger) error {
	if p.fetcher != nil {
		emitted, skipped, err := p.fetcher.PollOnce(ctx)
		if err != nil {
			return fmt.Errorf("fetch pass: %w", err)
		}
		logger.Info("fetch pass ok", "source", p.name, "emitted", emitted, "skipped", skipped)
		p.fetcher.LogExtraCounters(logger, p.name)
		if err := p.fetcher.SaveCheckpoint(); err != nil {
			return fmt.Errorf("saving fetch checkpoint: %w", err)
		}
	}
	result, err := p.indexer.ProcessNewLines(ctx)
	if err != nil {
		return fmt.Errorf("index pass: %w", err)
	}
	logIndexResult(logger, p.name, result)
	return nil
}

func (p *plane) FinalFlush(logger *slog.Logger) {
	if p.sink == nil {
		return
	}
	// ctx is already cancelled by now in the continuous path (that's what
	// stopped the loops) -- reusing it here would fail the flush
	// instantly, so this gets its own short-lived context.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.sink.Close(shutdownCtx); err != nil {
		logger.Error("final flush failed", "source", p.name, "error", err)
	}
	logSinkCounters(logger, "final index counters", p.name, p.sink)
}

func newContentPlane(cfg config, batchSize int, skipHealthchecks, dryRun, noFetch, noEnrich bool, fromTime time.Time) (*plane, error) {
	pl := &plane{name: "langfuse"}
	if !dryRun {
		pl.sink = esink.NewBulkIndexer(cfg.esClient(), cfg.indexBase,
			esink.WithBatchSize(batchSize),
			esink.WithDeadLetterPath(cfg.deadLetterPath))
	}
	ix, err := pipeline.NewIndexer(pipeline.IndexConfig{
		ArchivePath:      cfg.archivePath,
		StatePath:        cfg.indexStatePath,
		SkipHealthchecks: skipHealthchecks,
		DryRun:           dryRun,
		ECS:              cfg.ecsConfig(),
		Source:           model.SourceLangfuse,
	}, pl.sink, newLogger("json"))
	if err != nil {
		return nil, err
	}
	pl.indexer = ix

	if !noFetch {
		f, err := pipeline.NewFetcher(cfg.langfuseClient(), pipeline.FetchConfig{
			OutPath:           cfg.archivePath,
			StatePath:         cfg.fetchStatePath,
			SkipHealthchecks:  skipHealthchecks,
			From:              fromTime,
			Enrich:            !noEnrich,
			EnrichConcurrency: cfg.enrichConcurrency,
		})
		if err != nil {
			return nil, err
		}
		pl.fetcher = &contentPoller{f}
	}
	return pl, nil
}

func newGatewayPlane(cfg config, batchSize int, dryRun, noFetch bool, fromTime time.Time) (*plane, error) {
	pl := &plane{name: "litellm"}
	if !dryRun {
		pl.sink = esink.NewBulkIndexer(cfg.esClient(), cfg.gatewayIndexBase,
			esink.WithBatchSize(batchSize),
			esink.WithDeadLetterPath(cfg.gatewayDeadLetterPath))
	}
	ix, err := pipeline.NewIndexer(pipeline.IndexConfig{
		ArchivePath: cfg.gatewayArchivePath,
		StatePath:   cfg.gatewayIndexStatePath,
		// Health-check filtering is a Langfuse-tag concept; the gateway
		// plane has no equivalent tag, so nothing is dropped here.
		SkipHealthchecks: false,
		DryRun:           dryRun,
		ECS:              cfg.gatewayECSConfig(),
		Source:           model.SourceLiteLLM,
	}, pl.sink, newLogger("json"))
	if err != nil {
		return nil, err
	}
	pl.indexer = ix

	if !noFetch {
		f, err := pipeline.NewGatewayFetcher(cfg.litellmClient(), pipeline.GatewayFetchConfig{
			OutPath:   cfg.gatewayArchivePath,
			StatePath: cfg.gatewayFetchStatePath,
			From:      fromTime,
		})
		if err != nil {
			return nil, err
		}
		pl.fetcher = &gatewayPoller{f}
	}
	return pl, nil
}

// sourceSelection is which planes --sources asked for.
type sourceSelection struct{ langfuse, litellm bool }

func (s sourceSelection) String() string {
	switch {
	case s.langfuse && s.litellm:
		return "langfuse,litellm"
	case s.langfuse:
		return "langfuse"
	case s.litellm:
		return "litellm"
	}
	return "none"
}

func parseSources(spec string) (sourceSelection, error) {
	var sel sourceSelection
	for _, part := range strings.Split(spec, ",") {
		switch strings.TrimSpace(part) {
		case "":
			continue
		case "langfuse", "content":
			sel.langfuse = true
		case "litellm", "gateway":
			sel.litellm = true
		default:
			return sel, fmt.Errorf("unknown source %q in --sources (want langfuse and/or litellm)", part)
		}
	}
	if !sel.langfuse && !sel.litellm {
		return sel, fmt.Errorf("--sources=%q selected nothing", spec)
	}
	return sel, nil
}

// contentPoller and gatewayPoller adapt the two concrete fetchers to the
// poller interface. They exist so runFetchLoop's backoff, checkpointing
// and logging are written once rather than once per source -- the two
// fetchers differ in what they talk to, not in how they should be driven.
type contentPoller struct{ f *pipeline.Fetcher }

func (p *contentPoller) PollOnce(ctx context.Context) (int, int, error) { return p.f.PollOnce(ctx) }
func (p *contentPoller) SaveCheckpoint() error                          { return p.f.SaveCheckpoint() }
func (p *contentPoller) Close() error                                   { return p.f.Close() }
func (p *contentPoller) RunLoop(ctx context.Context, logger *slog.Logger, name string) {
	runFetchLoop(ctx, p, logger, name)
}
func (p *contentPoller) LogExtraCounters(logger *slog.Logger, name string) {
	c := p.f.EnrichCounters()
	if c.Attempted == 0 {
		return // enrichment off, or nothing new to enrich this pass
	}
	logger.Info("enrichment counters",
		"source", name,
		"attempted", c.Attempted,
		"succeeded", c.Succeeded,
		"skipped", c.Skipped,
		"failed", c.Failed,
	)
}

type gatewayPoller struct{ f *pipeline.GatewayFetcher }

func (p *gatewayPoller) PollOnce(ctx context.Context) (int, int, error) { return p.f.PollOnce(ctx) }
func (p *gatewayPoller) SaveCheckpoint() error                          { return p.f.SaveCheckpoint() }
func (p *gatewayPoller) Close() error                                   { return p.f.Close() }
func (p *gatewayPoller) RunLoop(ctx context.Context, logger *slog.Logger, name string) {
	runFetchLoop(ctx, p, logger, name)
}
func (p *gatewayPoller) LogExtraCounters(*slog.Logger, string) {
	// The gateway fetch has no enrichment stage: /spend/logs/v2 returns
	// complete records in one call, so there is no N+1 detail fetch and
	// nothing extra to count.
}

// runFetchLoop polls on defaultFetchInterval with capped exponential
// backoff on failure, until ctx is cancelled.
//
// It never returns on a source error -- only on ctx cancellation. That is
// the mechanism behind "one source failing must not stop the other": a
// Langfuse outage makes this loop back off and retry forever, and the
// gateway's loop, running in its own goroutine over its own state, never
// observes it.
func runFetchLoop(ctx context.Context, p poller, logger *slog.Logger, name string) {
	backoff := 1 * time.Second
	const maxBackoff = 5 * time.Minute

	for {
		emitted, skipped, err := p.PollOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("fetch poll failed", "source", name, "error", err, "retry_in", backoff.String())
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		backoff = 1 * time.Second
		logger.Info("fetch poll ok", "source", name, "emitted", emitted, "skipped", skipped)
		p.LogExtraCounters(logger, name)
		if err := p.SaveCheckpoint(); err != nil {
			logger.Error("fetch checkpoint save failed", "source", name, "error", err)
		}

		if !sleepCtx(ctx, defaultFetchInterval) {
			return
		}
	}
}

// runIndexLoop scans one plane's archive for new lines every interval,
// until ctx is cancelled. Like runFetchLoop it survives its own errors, so
// an Elasticsearch problem affecting one index cannot stop the other.
func runIndexLoop(ctx context.Context, ix *pipeline.Indexer, logger *slog.Logger, name string, interval time.Duration) {
	for {
		result, err := ix.ProcessNewLines(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("index pass failed", "source", name, "error", err)
		} else {
			logIndexResult(logger, name, result)
		}

		if !sleepCtx(ctx, interval) {
			return
		}
	}
}

func logIndexResult(logger *slog.Logger, name string, result pipeline.IndexResult) {
	logger.Info("index pass ok",
		"source", name,
		"lines", result.Lines,
		"parsed", result.Parsed,
		"parse_errors", result.ParseErrors,
		"skipped", result.Skipped,
		"queued", result.Queued,
	)
}

func logSinkCounters(logger *slog.Logger, msg, name string, sink *esink.BulkIndexer) {
	c := sink.Counters()
	logger.Info(msg,
		"source", name,
		"attempted", c.Attempted,
		"indexed", c.Indexed,
		"failed", c.Failed,
		"retried", c.Retried,
		"dead_lettered", c.DeadLettered,
	)
}

func newJoinHealthReporter(cfg config, flushInterval time.Duration) (*pipeline.JoinHealthReporter, error) {
	return pipeline.NewJoinHealthReporter(cfg.esClient(), pipeline.JoinHealthConfig{
		ContentIndex: cfg.indexBase,
		GatewayIndex: cfg.gatewayIndexBase,
		Window:       pipeline.DefaultJoinHealthWindow,
		// Derived from this process's own poll intervals rather than
		// fixed: a longer flush interval genuinely delays documents, and
		// a fixed lag would then report a healthy pipeline as broken
		// every cycle. See pipeline.JoinHealthLag.
		Lag:          pipeline.JoinHealthLag(defaultFetchInterval, flushInterval),
		BaselinePath: cfg.joinBaselinePath,
	})
}

// joinHealthInterval is how often the join is measured. Deliberately
// slower than the index loop: the measurement window is 15 minutes wide,
// so reporting more often than this mostly re-reports the same events.
const joinHealthInterval = 5 * time.Minute

// runJoinHealthLoop periodically reports how well the two planes are
// joining.
//
// This is the single most important operational signal wiretapd produces,
// because it is the only thing that distinguishes "no attacks" from "the
// join is broken". A silent join failure looks exactly like an absence of
// findings; this loop is what makes that distinction observable rather
// than assumed. See docs/CORRELATION.md §2.
func runJoinHealthLoop(ctx context.Context, r *pipeline.JoinHealthReporter, logger *slog.Logger) {
	logger.Info("join health enabled",
		"baseline_trace_ids", r.BaselineSize(),
		"interval", joinHealthInterval.String(),
	)
	// One measurement immediately, so a broken join is visible at startup
	// rather than five minutes later.
	for {
		res, err := r.Measure(ctx, time.Now().UTC())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// A failed measurement is NOT a healthy join. Logged at error
			// so it can never be mistaken for a zero unmatched rate.
			logger.Error("join health measurement failed", "error", err)
		} else {
			logJoinHealth(logger, res)
		}
		if !sleepCtx(ctx, joinHealthInterval) {
			return
		}
	}
}

func logJoinHealth(logger *slog.Logger, res pipeline.JoinHealthResult) {
	attrs := []any{
		"window_start", res.WindowStart.Format(time.RFC3339),
		"window_end", res.WindowEnd.Format(time.RFC3339),
		"content_total", res.ContentTotal,
		"content_matched", res.ContentMatched,
		"content_expected_unmatched", res.ContentExpectedUnmatched,
		"content_unexplained", res.ContentUnexplained,
		"content_unexplained_rate", res.ContentUnexplainedRate(),
		"gateway_total", res.GatewayTotal,
		"gateway_matched", res.GatewayMatched,
		"gateway_expected_unmatched", res.GatewayExpectedUnmatched,
		"gateway_unexplained", res.GatewayUnexplained,
		"gateway_unexplained_rate", res.GatewayUnexplainedRate(),
		"gateway_docs", res.GatewayDocs,
		"gateway_docs_without_join_key", res.GatewayDocsWithoutJoinKey,
	}
	if res.Healthy() {
		logger.Info("join health ok", attrs...)
		return
	}
	// Warn, not Info: an unexplained unmatched event means either a
	// request bypassed the gateway, a fetcher has stalled, or the join key
	// stopped being sent. All three are incidents.
	logger.Warn("join health degraded", attrs...)
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
