package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"wiretap/internal/esink"
	"wiretap/internal/pipeline"
)

func cmdBackfill(args []string) error {
	fs := flag.NewFlagSet("backfill", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "map and print documents instead of indexing them")
	batchSize := fs.Int("batch-size", 100, "bulk indexing batch size")
	skipHealthchecks := fs.Bool("skip-healthchecks", true, "drop litellm-internal-health-check events before indexing")
	logFormat := fs.String("log-format", "json", "log format: json or text")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := newLogger(*logFormat)
	cfg, err := loadConfig()
	if err != nil {
		return err
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	logger.Info("backfill starting", "archive", cfg.archivePath)
	result, err := ix.Backfill(ctx)
	if err != nil {
		return fmt.Errorf("backfill: %w", err)
	}

	logger.Info("backfill complete",
		"lines", result.Lines,
		"parsed", result.Parsed,
		"parse_errors", result.ParseErrors,
		"skipped", result.Skipped,
		"queued", result.Queued,
	)

	if sink != nil {
		c := sink.Counters()
		logger.Info("backfill index counters",
			"attempted", c.Attempted,
			"indexed", c.Indexed,
			"failed", c.Failed,
			"retried", c.Retried,
			"dead_lettered", c.DeadLettered,
		)
	}
	return nil
}
