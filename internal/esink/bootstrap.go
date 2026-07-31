package esink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// SharedIndexPattern is the pattern a Kibana data view (and any
// cross-plane query) should point at to see both datasets at once.
//
// Both index bases below deliberately start with "wiretap-llm-" so this
// one pattern covers them. That is what lets a single data view -- and,
// more importantly, an EQL sequence query, which cannot span two data
// views -- correlate a content event with a gateway event. The two are
// told apart by event.dataset, never by which index they came from.
const SharedIndexPattern = "wiretap-llm-*"

// Default index bases for the two datasets. Content keeps its original
// name so no existing data has to be migrated for a purely cosmetic
// symmetry with the gateway's.
const (
	DefaultContentIndexBase = "wiretap-llm-events"
	DefaultGatewayIndexBase = "wiretap-llm-gateway"
)

// Dataset selects which mapping an index template gets. The two datasets
// share most of their schema (see sharedProperties) and differ only in the
// fields one plane can report and the other structurally cannot.
type Dataset int

const (
	// DatasetContent is the Langfuse content plane: prompts, responses,
	// generation counts. event.dataset "wiretap.langfuse".
	DatasetContent Dataset = iota
	// DatasetGateway is the LiteLLM gateway plane: key identity, HTTP
	// status, structured error class. event.dataset "wiretap.litellm".
	DatasetGateway
)

func (d Dataset) String() string {
	if d == DatasetGateway {
		return "gateway"
	}
	return "content"
}

// mapping returns the explicit field mapping for this dataset.
func (d Dataset) mapping() map[string]any {
	if d == DatasetGateway {
		return gatewayIndexMapping()
	}
	return contentIndexMapping()
}

// BootstrapConfig names the index template, concrete index, and write
// alias Bootstrap creates for one dataset. IndexBase and Dataset are the
// only things callers choose; the template name and concrete index name
// are both derived from IndexBase so they can never drift apart from the
// alias they're meant to back.
type BootstrapConfig struct {
	// IndexBase names the alias documents are actually indexed through
	// (e.g. "wiretap-llm-events"). The concrete index backing it is
	// IndexBase + "-000001".
	IndexBase string
	// Dataset selects the mapping. The zero value is DatasetContent,
	// which keeps every existing caller correct without change.
	Dataset Dataset
}

// DefaultBootstrapConfigs returns the configs for both datasets, in the
// order they should be created. Callers that want non-default index names
// build their own.
func DefaultBootstrapConfigs() []BootstrapConfig {
	return []BootstrapConfig{
		{IndexBase: DefaultContentIndexBase, Dataset: DatasetContent},
		{IndexBase: DefaultGatewayIndexBase, Dataset: DatasetGateway},
	}
}

// BootstrapAll creates every config's template and index, and is what
// `wiretapd bootstrap` calls. It does not stop at the first failure:
// bootstrapping the gateway index must not be prevented by an unrelated
// problem with the content one, for the same reason the two fetchers are
// independent (see cmd/wiretapd). Every error encountered is returned
// joined, so a caller sees all of them rather than the first.
func (c *Client) BootstrapAll(ctx context.Context, cfgs []BootstrapConfig) error {
	var errs []error
	for _, cfg := range cfgs {
		if err := c.Bootstrap(ctx, cfg); err != nil {
			errs = append(errs, fmt.Errorf("%s dataset: %w", cfg.Dataset, err))
		}
	}
	return errors.Join(errs...)
}

// TemplateName is the index template Bootstrap creates for cfg. Exported so
// callers outside this package (cmd/wiretapd's "check" preflight) can ask
// TemplateExists about the same name Bootstrap itself uses, without
// duplicating the "-template" suffix convention.
func (cfg BootstrapConfig) TemplateName() string  { return cfg.IndexBase + "-template" }
func (cfg BootstrapConfig) indexPattern() string  { return cfg.IndexBase + "-*" }
func (cfg BootstrapConfig) concreteIndex() string { return cfg.IndexBase + "-000001" }

// Bootstrap creates the index template (with explicit mappings for this
// dataset -- see mapping.go) and, if it doesn't already exist, the first concrete index,
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
			"mappings": cfg.Dataset.mapping(),
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
