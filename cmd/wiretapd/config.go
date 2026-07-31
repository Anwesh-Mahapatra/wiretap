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
	"wiretap/internal/litellm"
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
	// indexBase is the content plane's write alias; gatewayIndexBase is
	// the gateway plane's. Two indices behind one shared pattern, told
	// apart by event.dataset -- see docs/CORRELATION.md §3 and
	// esink.SharedIndexPattern.
	indexBase        string
	gatewayIndexBase string

	// Gateway-plane paths. Every one of these is a DISTINCT file from its
	// content-plane counterpart above, and that is load-bearing rather
	// than tidy: each archive must have exactly one writer and each
	// checkpoint exactly one owner, which is the invariant that keeps two
	// fetchers from reproducing the duplicate-writer race described in
	// arch.md. Nothing here defaults to a path the content plane also
	// uses.
	gatewayArchivePath    string
	gatewayFetchStatePath string
	gatewayIndexStatePath string

	// Dead-letter files, one per plane. These defaulted to a single
	// shared "dead-letter.json" -- appends would not have corrupted bytes,
	// but esink.DeadLetterRecord carries no dataset field, so a replay
	// could not tell which index a failed document belonged to.
	deadLetterPath        string
	gatewayDeadLetterPath string

	// litellmBaseURL / litellmMasterKey reach the gateway's spend API.
	// The master key is the most privileged credential in this
	// deployment; it is read here and passed to internal/litellm, and
	// never logged (see that package's doc comment).
	litellmBaseURL   string
	litellmMasterKey string

	// joinBaselinePath points at join-baseline.json -- the closed set of
	// trace IDs that can never be joined because they predate the client
	// sending the join key. See internal/pipeline's JoinHealthReporter.
	joinBaselinePath string

	// enrichConcurrency bounds how many GetTrace calls the fetch stage
	// runs at once when enrichment is on (see pipeline.FetchConfig.Enrich
	// and internal/pipeline/enrich.go). 0 means "use the package default"
	// (4).
	enrichConcurrency int
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

		archivePath:      env.OrDefault("WIRETAPD_ARCHIVE", "/data/langfuse-traces.ndjson"),
		fetchStatePath:   env.OrDefault("WIRETAPD_FETCH_STATE", "wiretapd-fetch-state.json"),
		indexStatePath:   env.OrDefault("WIRETAPD_INDEX_STATE", "wiretapd-index-state.json"),
		indexBase:        env.OrDefault("WIRETAPD_INDEX_BASE", esink.DefaultContentIndexBase),
		gatewayIndexBase: env.OrDefault("WIRETAPD_GATEWAY_INDEX_BASE", esink.DefaultGatewayIndexBase),

		gatewayArchivePath:    env.OrDefault("WIRETAPD_GATEWAY_ARCHIVE", "/data/litellm-spend.ndjson"),
		gatewayFetchStatePath: env.OrDefault("WIRETAPD_GATEWAY_FETCH_STATE", "wiretapd-gateway-fetch-state.json"),
		gatewayIndexStatePath: env.OrDefault("WIRETAPD_GATEWAY_INDEX_STATE", "wiretapd-gateway-index-state.json"),

		deadLetterPath:        env.OrDefault("WIRETAPD_DEAD_LETTER", "dead-letter.json"),
		gatewayDeadLetterPath: env.OrDefault("WIRETAPD_GATEWAY_DEAD_LETTER", "dead-letter-gateway.json"),

		litellmBaseURL:   env.OrDefault("LITELLM_BASE_URL", "http://localhost:4000"),
		litellmMasterKey: os.Getenv("LITELLM_MASTER_KEY"),

		joinBaselinePath: env.OrDefault("WIRETAPD_JOIN_BASELINE", "join-baseline.json"),
	}

	if v := os.Getenv("ELASTICSEARCH_TLS_SKIP_VERIFY"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return cfg, fmt.Errorf("parsing ELASTICSEARCH_TLS_SKIP_VERIFY=%q: %w", v, err)
		}
		cfg.esTLSSkipVerify = b
	}

	if v := os.Getenv("WIRETAPD_ENRICH_CONCURRENCY"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return cfg, fmt.Errorf("parsing WIRETAPD_ENRICH_CONCURRENCY=%q: %w", v, err)
		}
		cfg.enrichConcurrency = n
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

func (c config) gatewayECSConfig() ecs.Config {
	return ecs.DefaultGatewayConfig()
}

func (c config) litellmClient() *litellm.Client {
	return litellm.New(c.litellmBaseURL, c.litellmMasterKey)
}

// validatePathIsolation is a startup assertion, not a style check. Two
// fetchers writing one archive, or two indexers sharing one checkpoint, is
// precisely the failure mode removing tracepump from compose solved (see
// arch.md). Every one of these paths is independently overridable by an
// environment variable, so "they are different by default" is not a
// guarantee -- one typo in a compose file collapses two of them onto the
// same file and the symptom is silently lost or duplicated data, not an
// error.
func (c config) validatePathIsolation() error {
	paths := map[string]string{
		"WIRETAPD_ARCHIVE":             c.archivePath,
		"WIRETAPD_GATEWAY_ARCHIVE":     c.gatewayArchivePath,
		"WIRETAPD_FETCH_STATE":         c.fetchStatePath,
		"WIRETAPD_GATEWAY_FETCH_STATE": c.gatewayFetchStatePath,
		"WIRETAPD_INDEX_STATE":         c.indexStatePath,
		"WIRETAPD_GATEWAY_INDEX_STATE": c.gatewayIndexStatePath,
		"WIRETAPD_DEAD_LETTER":         c.deadLetterPath,
		"WIRETAPD_GATEWAY_DEAD_LETTER": c.gatewayDeadLetterPath,
	}
	seen := make(map[string]string, len(paths))
	for name, path := range paths {
		if path == "" {
			return fmt.Errorf("%s is empty; every archive, checkpoint and dead-letter path must be set", name)
		}
		if other, dup := seen[path]; dup {
			return fmt.Errorf("%s and %s are both %q -- two writers on one file is the duplicate-writer race arch.md describes; give them separate paths", other, name, path)
		}
		seen[path] = name
	}
	if c.indexBase == c.gatewayIndexBase {
		return fmt.Errorf("WIRETAPD_INDEX_BASE and WIRETAPD_GATEWAY_INDEX_BASE are both %q -- the two planes have different mappings and must not share an index", c.indexBase)
	}
	return nil
}

// bootstrapConfig is the content plane's index config. Kept as its own
// method because `check` asks specifically about the content template.
func (c config) bootstrapConfig() esink.BootstrapConfig {
	return esink.BootstrapConfig{IndexBase: c.indexBase, Dataset: esink.DatasetContent}
}

// gatewayBootstrapConfig is the gateway plane's.
func (c config) gatewayBootstrapConfig() esink.BootstrapConfig {
	return esink.BootstrapConfig{IndexBase: c.gatewayIndexBase, Dataset: esink.DatasetGateway}
}

// bootstrapConfigs is every index this deployment needs, which is what
// `wiretapd bootstrap` creates.
func (c config) bootstrapConfigs() []esink.BootstrapConfig {
	return []esink.BootstrapConfig{c.bootstrapConfig(), c.gatewayBootstrapConfig()}
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
