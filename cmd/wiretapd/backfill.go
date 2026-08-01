package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"wiretap/internal/ecs"
	"wiretap/internal/esink"
	"wiretap/internal/model"
	"wiretap/internal/pipeline"
)

func cmdBackfill(args []string) error {
	fs := flag.NewFlagSet("backfill", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "map and print documents instead of indexing them")
	batchSize := fs.Int("batch-size", 100, "bulk indexing batch size")
	skipHealthchecks := fs.Bool("skip-healthchecks", true, "drop litellm-internal-health-check events, on both planes, before indexing")
	logFormat := fs.String("log-format", "json", "log format: json or text")
	sources := fs.String("sources", "langfuse,litellm", "comma-separated sources to replay: langfuse (content plane), litellm (gateway plane), or both")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := newLogger(*logFormat)
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := cfg.validatePathIsolation(); err != nil {
		return err
	}
	sel, err := parseSources(*sources)
	if err != nil {
		return err
	}

	type target struct {
		name    string
		archive string
		state   string
		index   string
		deadLtr string
		ecs     ecs.Config
		source  model.Source
		skipHC  bool
	}
	var targets []target
	if sel.langfuse {
		targets = append(targets, target{
			name: "langfuse", archive: cfg.archivePath, state: cfg.indexStatePath,
			index: cfg.indexBase, deadLtr: cfg.deadLetterPath,
			ecs: cfg.ecsConfig(), source: model.SourceLangfuse, skipHC: *skipHealthchecks,
		})
	}
	if sel.litellm {
		targets = append(targets, target{
			name: "litellm", archive: cfg.gatewayArchivePath, state: cfg.gatewayIndexStatePath,
			index: cfg.gatewayIndexBase, deadLtr: cfg.gatewayDeadLetterPath,
			ecs: cfg.gatewayECSConfig(), source: model.SourceLiteLLM, skipHC: *skipHealthchecks,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Each source is replayed independently and a failure in one does not
	// abandon the other: replaying the gateway archive must not be
	// prevented by an unrelated problem with the content one. Errors are
	// collected and returned together.
	var errs []error
	for _, tg := range targets {
		// A missing archive is "this source has never run", not a
		// failure -- and is the normal state when backfilling both
		// sources on a stack that only ever ran one.
		if _, statErr := os.Stat(tg.archive); statErr != nil && os.IsNotExist(statErr) {
			logger.Info("backfill skipped: archive does not exist", "source", tg.name, "archive", tg.archive)
			continue
		}

		var sink *esink.BulkIndexer
		if !*dryRun {
			sink = esink.NewBulkIndexer(cfg.esClient(), tg.index,
				esink.WithBatchSize(*batchSize),
				esink.WithDeadLetterPath(tg.deadLtr))
		}

		ix, ierr := pipeline.NewIndexer(pipeline.IndexConfig{
			ArchivePath:      tg.archive,
			StatePath:        tg.state,
			SkipHealthchecks: tg.skipHC,
			DryRun:           *dryRun,
			ECS:              tg.ecs,
			Source:           tg.source,
		}, sink, logger)
		if ierr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", tg.name, ierr))
			continue
		}

		logger.Info("backfill starting", "source", tg.name, "archive", tg.archive, "index", tg.index)
		result, berr := ix.Backfill(ctx)
		if berr != nil {
			errs = append(errs, fmt.Errorf("%s: backfill: %w", tg.name, berr))
			continue
		}

		logger.Info("backfill complete",
			"source", tg.name,
			"lines", result.Lines,
			"parsed", result.Parsed,
			"parse_errors", result.ParseErrors,
			"skipped", result.Skipped,
			"queued", result.Queued,
		)

		if sink != nil {
			if cerr := sink.Close(ctx); cerr != nil {
				errs = append(errs, fmt.Errorf("%s: final flush: %w", tg.name, cerr))
			}
			logSinkCounters(logger, "backfill index counters", tg.name, sink)
		}
	}
	return errors.Join(errs...)
}
