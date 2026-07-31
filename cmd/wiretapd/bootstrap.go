package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"wiretap/internal/esink"
)

func cmdBootstrap(args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	logFormat := fs.String("log-format", "json", "log format: json or text")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := newLogger(*logFormat)
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Both datasets, every run. Idempotent: PUTting the same template
	// twice is a plain overwrite, and index creation is skipped when the
	// index already exists -- so this is safe to run on every deploy and
	// is how a new gateway index gets created on an existing stack.
	cfgs := cfg.bootstrapConfigs()
	if err := cfg.esClient().BootstrapAll(ctx, cfgs); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}

	for _, bcfg := range cfgs {
		logger.Info("bootstrap complete",
			"dataset", bcfg.Dataset.String(),
			"index_base", bcfg.IndexBase,
			"template", bcfg.TemplateName(),
		)
	}
	logger.Info("shared index pattern for cross-plane queries", "pattern", esink.SharedIndexPattern)
	return nil
}
