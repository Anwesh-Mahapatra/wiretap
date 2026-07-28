package main

import (
	"context"
	"flag"
	"fmt"
	"time"
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

	bcfg := cfg.bootstrapConfig()
	if err := cfg.esClient().Bootstrap(ctx, bcfg); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}

	logger.Info("bootstrap complete", "index_base", bcfg.IndexBase, "template", bcfg.TemplateName())
	return nil
}
