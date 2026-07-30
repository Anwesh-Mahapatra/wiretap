package esink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// BootstrapConfig names the index template, concrete index, and write
// alias Bootstrap creates. IndexBase is the only thing callers need to
// choose; the template name and concrete index name are both derived from
// it so they can never drift apart from the alias they're meant to back.
type BootstrapConfig struct {
	// IndexBase names the alias documents are actually indexed through
	// (e.g. "wiretap-llm-events"). The concrete index backing it is
	// IndexBase + "-000001".
	IndexBase string
}

// TemplateName is the index template Bootstrap creates for cfg. Exported so
// callers outside this package (cmd/wiretapd's "check" preflight) can ask
// TemplateExists about the same name Bootstrap itself uses, without
// duplicating the "-template" suffix convention.
func (cfg BootstrapConfig) TemplateName() string  { return cfg.IndexBase + "-template" }
func (cfg BootstrapConfig) indexPattern() string  { return cfg.IndexBase + "-*" }
func (cfg BootstrapConfig) concreteIndex() string { return cfg.IndexBase + "-000001" }

// Bootstrap creates the index template (with explicit mappings -- see
// indexMapping) and, if it doesn't already exist, the first concrete index,
// which the template's own aliases block wires up to IndexBase
// automatically on creation. Both steps are idempotent: PUTting the same
// template definition twice is a plain overwrite (Elasticsearch's own
// semantics, not something this code has to work around), and the index
// creation step is skipped entirely if the index is already there --
// running Bootstrap twice never errors.
func (c *Client) Bootstrap(ctx context.Context, cfg BootstrapConfig) error {
	templateBody, err := json.Marshal(map[string]any{
		"index_patterns": []string{cfg.indexPattern()},
		"template": map[string]any{
			"settings": map[string]any{
				// Single-node lab cluster (see docker-compose.yml): one
				// shard is plenty, and requiring replicas would leave the
				// index permanently yellow with nowhere to put them.
				"number_of_shards":   1,
				"number_of_replicas": 0,
			},
			"mappings": indexMapping(),
			"aliases": map[string]any{
				cfg.IndexBase: map[string]any{
					"is_write_index": true,
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("encoding index template: %w", err)
	}

	if _, err := c.do(ctx, http.MethodPut, "/_index_template/"+cfg.TemplateName(), "application/json", templateBody); err != nil {
		return fmt.Errorf("creating index template %q: %w", cfg.TemplateName(), err)
	}

	exists, err := c.indexExists(ctx, cfg.concreteIndex())
	if err != nil {
		return fmt.Errorf("checking whether index %q exists: %w", cfg.concreteIndex(), err)
	}
	if exists {
		return nil
	}

	// No body needed: the index template matching this name's pattern
	// supplies settings/mappings/aliases automatically.
	if _, err := c.do(ctx, http.MethodPut, "/"+cfg.concreteIndex(), "", nil); err != nil {
		return fmt.Errorf("creating index %q: %w", cfg.concreteIndex(), err)
	}
	return nil
}

func (c *Client) indexExists(ctx context.Context, index string) (bool, error) {
	return c.exists(ctx, "/"+index)
}

// TemplateExists reports whether the index template Bootstrap would create
// for cfg already exists -- used by cmd/wiretapd's "check" preflight to
// distinguish "never bootstrapped" from every other kind of failure.
func (c *Client) TemplateExists(ctx context.Context, cfg BootstrapConfig) (bool, error) {
	return c.exists(ctx, "/_index_template/"+cfg.TemplateName())
}

func (c *Client) exists(ctx context.Context, path string) (bool, error) {
	_, err := c.do(ctx, http.MethodHead, path, "", nil)
	if err == nil {
		return true, nil
	}
	var esErr *Error
	if errors.As(err, &esErr) && esErr.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, err
}

// Ping confirms the cluster is reachable and, if credentials were
// configured, that they're accepted -- a lightweight GET against the root
// endpoint, which Elasticsearch always answers once it's up.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodGet, "/", "", nil)
	return err
}

// indexMapping is the explicit field mapping for wiretap's ECS documents
// (see internal/ecs.Document). No field here is left to dynamic mapping --
// every key a Document can produce has a deliberate type below, chosen
// against docs/reference/ecs-gen_ai.md's own type column where a field
// comes from that fieldset.
//
// Two choices worth explaining inline rather than leaving implicit:
//
//   - llm.output and llm.user_prompt use Elasticsearch's "wildcard" type,
//     not "keyword" or "text". The canary-token detection this project
//     exists to demonstrate (see docs/DETECTIONS.md) is a leading-wildcard
//     query, llm.output: *XK9-Canaries-77*. Leading wildcards are slow (and
//     disabled by default) on "keyword", and "text"'s standard analyzer
//     tokenizes on non-alphanumeric characters, which would silently break
//     a substring match against a token containing punctuation or mixed
//     case. "wildcard" exists in Elasticsearch specifically for this
//     access pattern. Getting this one wrong doesn't break loudly -- the
//     query just quietly returns nothing, which is why it's called out
//     here instead of left for someone to discover the hard way.
//   - llm.messages is "text" with "index": false. It exists for an analyst
//     to read the full conversation when they click into a document, not
//     to be searched -- the fields that matter for detection are
//     llm.output and llm.user_prompt, the current turn, already broken out
//     separately. Indexing the same content a second time (as wildcard,
//     to make it searchable too) would roughly double this field's storage
//     for a capability nothing in docs/DETECTIONS.md uses; index: false
//     keeps it in _source (still retrievable, still displayable) without
//     paying that cost.
func indexMapping() map[string]any {
	keyword := map[string]any{"type": "keyword"}
	integer := map[string]any{"type": "integer"}
	double := map[string]any{"type": "double"}
	date := map[string]any{"type": "date"}
	long := map[string]any{"type": "long"}
	wildcard := map[string]any{"type": "wildcard"}

	return map[string]any{
		"properties": map[string]any{
			"@timestamp": date,
			"ecs": map[string]any{
				"properties": map[string]any{"version": keyword},
			},
			"event": map[string]any{
				"properties": map[string]any{
					"kind":      keyword,
					"category":  keyword,
					"dataset":   keyword,
					"module":    keyword,
					"duration":  long,
					"ingested":  date,
					"reference": keyword,
				},
			},
			"trace":   map[string]any{"properties": map[string]any{"id": keyword}},
			"session": map[string]any{"properties": map[string]any{"id": keyword}},
			"user":    map[string]any{"properties": map[string]any{"id": keyword}},
			"gen_ai": map[string]any{
				"properties": map[string]any{
					"system":    keyword,
					"operation": map[string]any{"properties": map[string]any{"name": keyword}},
					"request": map[string]any{
						"properties": map[string]any{
							"model":      keyword,
							"max_tokens": integer,
						},
					},
					"response": map[string]any{
						"properties": map[string]any{
							"model": keyword,
							"id":    keyword,
							// No finish_reasons mapping: internal/ecs's
							// genAIResponse doesn't have that field.
							// Confirmed genuinely unavailable from this
							// project's Langfuse data (see
							// internal/ecs/genai.go's package doc and
							// notes.md) -- mapping a field the document
							// never sends would be dead, misleading
							// schema.
						},
					},
					"usage": map[string]any{
						"properties": map[string]any{
							"input_tokens":  integer,
							"output_tokens": integer,
						},
					},
				},
			},
			"llm": map[string]any{
				"properties": map[string]any{
					"system_prompt":  map[string]any{"type": "text"},
					"user_prompt":    wildcard,
					"output":         wildcard,
					"output_role":    keyword,
					"messages":       map[string]any{"type": "text", "index": false},
					"message_count":  integer,
					"output_length":  integer,
					"total_cost_usd": double,
					// generation_count: how many GENERATION observations
					// contributed to gen_ai.usage.* above (see
					// internal/parse's applyGenerations). Small, bounded
					// counter -- integer, same reasoning as message_count/
					// output_length above.
					"generation_count": integer,
				},
			},
			"labels": map[string]any{
				"properties": map[string]any{
					"wiretap_outcome":  keyword,
					"wiretap_scenario": keyword,
				},
			},
			"tags": keyword,
		},
	}
}
