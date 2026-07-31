// Package esink is wiretap's Elasticsearch sink: bootstrapping the index
// template + alias (see bootstrap.go) and bulk-indexing ECS documents (see
// bulk.go). It is the only package that talks to Elasticsearch directly.
package esink

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultTimeout = 30 * time.Second

// Client is a thin Elasticsearch HTTP client: authentication, TLS
// configuration, and typed error classification, with no Elasticsearch
// API-specific logic of its own -- that lives in bootstrap.go and bulk.go.
type Client struct {
	baseURL    string
	httpClient *http.Client
	username   string
	password   string
}

// Option configures a Client constructed by New.
type Option func(*Client)

// WithBasicAuth sets HTTP Basic Auth credentials (e.g. the "elastic" user).
func WithBasicAuth(username, password string) Option {
	return func(c *Client) { c.username = username; c.password = password }
}

// WithInsecureSkipVerify disables TLS certificate verification. Off by
// default -- only for local labs talking to a self-signed or unconfigured
// TLS endpoint; never enable this against anything reachable outside the
// machine running it.
func WithInsecureSkipVerify() Option {
	return func(c *Client) {
		tr, ok := c.httpClient.Transport.(*http.Transport)
		if !ok || tr == nil {
			tr = http.DefaultTransport.(*http.Transport).Clone()
		} else {
			tr = tr.Clone()
		}
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit, opt-in, documented lab-only escape hatch
		c.httpClient.Transport = tr
	}
}

// WithHTTPClient overrides the default *http.Client (30s timeout,
// otherwise stdlib defaults).
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// New returns a Client for the Elasticsearch cluster at baseURL.
func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// do sends one HTTP request and returns its body, classifying any non-2xx
// status or transport failure into a typed *Error. It does not retry --
// retry policy differs enough between a one-shot bootstrap call and a
// hot-path bulk request that it belongs in each caller, not here.
func (c *Client) do(ctx context.Context, method, path, contentType string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &Error{Kind: ErrTransport, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &Error{Kind: ErrTransport, Err: fmt.Errorf("reading response body: %w", err)}
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return respBody, nil
	}
	return respBody, classifyStatus(resp.StatusCode, resp.Status, respBody, resp.Header)
}

// Search runs a search against index (which may be an alias or a pattern)
// and returns the raw response body. Exists so callers that need to *read*
// from Elasticsearch -- the join-health metric, notably -- do not each
// reimplement request plumbing, auth, and error classification.
func (c *Client) Search(ctx context.Context, index string, body any) (json.RawMessage, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encoding search body: %w", err)
	}
	resp, err := c.do(ctx, http.MethodPost, "/"+index+"/_search", "application/json", encoded)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(resp), nil
}
