package main

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"wiretap/internal/ecs"
	"wiretap/internal/env"
	"wiretap/internal/esink"
	"wiretap/internal/langfuse"
)

const defaultEnvFile = ".env"

// config is the environment-derived configuration every subcommand shares.
// Flags (parsed separately per subcommand, since not every flag applies to
// every subcommand) layer on top of this, never the other way around.
type config struct {
	// langfuseBaseURL is what the Fetcher actually connects to -- inside
	// the wiretapd container this must be http://langfuse-web:3000 (see
	// docker-compose.yml), not localhost.
	langfuseBaseURL string
	// langfusePublicURL is what an *analyst's browser* would use to reach
	// the same Langfuse instance -- used only to build event.reference
	// links (see internal/ecs.Config.LangfuseBaseURL). Deliberately a
	// separate setting from langfuseBaseURL: inside a container the two
	// are never the same value, and conflating them would produce
	// Kibana-alert links that only resolve from inside Docker's network.
	langfusePublicURL string
	langfusePublicKey string
	langfuseSecretKey string

	esURL           string
	esUsername      string
	esPassword      string
	esTLSSkipVerify bool

	archivePath    string
	fetchStatePath string
	indexStatePath string
	indexBase      string
}

func loadConfig() (config, error) {
	if err := env.LoadDotEnv(defaultEnvFile); err != nil {
		return config{}, err
	}

	cfg := config{
		langfuseBaseURL:   env.OrDefault("LANGFUSE_BASE_URL", "http://localhost:3000"),
		langfusePublicURL: env.OrDefault("LANGFUSE_PUBLIC_URL", env.OrDefault("LANGFUSE_BASE_URL", "http://localhost:3000")),
		langfusePublicKey: os.Getenv("LANGFUSE_PUBLIC_KEY"),
		langfuseSecretKey: os.Getenv("LANGFUSE_SECRET_KEY"),

		esURL:      env.OrDefault("ELASTICSEARCH_URL", "http://localhost:9200"),
		esUsername: env.OrDefault("ELASTIC_USERNAME", "elastic"),
		esPassword: os.Getenv("ELASTIC_PASSWORD"),

		archivePath:    env.OrDefault("WIRETAPD_ARCHIVE", "/data/langfuse-traces.ndjson"),
		fetchStatePath: env.OrDefault("WIRETAPD_FETCH_STATE", "wiretapd-fetch-state.json"),
		indexStatePath: env.OrDefault("WIRETAPD_INDEX_STATE", "wiretapd-index-state.json"),
		indexBase:      env.OrDefault("WIRETAPD_INDEX_BASE", "wiretap-llm-events"),
	}

	if v := os.Getenv("ELASTICSEARCH_TLS_SKIP_VERIFY"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return cfg, fmt.Errorf("parsing ELASTICSEARCH_TLS_SKIP_VERIFY=%q: %w", v, err)
		}
		cfg.esTLSSkipVerify = b
	}

	if cfg.langfusePublicKey == "" || cfg.langfuseSecretKey == "" {
		return cfg, fmt.Errorf("LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY must be set (in the environment or .env)")
	}

	return cfg, nil
}

func (c config) langfuseClient() *langfuse.Client {
	return langfuse.New(c.langfuseBaseURL, c.langfusePublicKey, c.langfuseSecretKey, langfuse.WithUserAgent("wiretapd"))
}

func (c config) esClient() *esink.Client {
	opts := []esink.Option{esink.WithBasicAuth(c.esUsername, c.esPassword)}
	if c.esTLSSkipVerify {
		opts = append(opts, esink.WithInsecureSkipVerify())
	}
	return esink.New(c.esURL, opts...)
}

func (c config) ecsConfig() ecs.Config {
	return ecs.DefaultConfig(c.langfusePublicURL)
}

func (c config) bootstrapConfig() esink.BootstrapConfig {
	return esink.BootstrapConfig{IndexBase: c.indexBase}
}

// newLogger builds the shared structured logger: JSON to stderr by
// default, human-readable with --log-format=text. See this file's package
// doc for why info-level logging never includes prompt/completion content.
func newLogger(format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(handler)
}
