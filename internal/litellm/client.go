// Package litellm is a minimal client for the subset of LiteLLM's proxy
// admin API wiretap needs: listing per-request spend records (paginated,
// filterable by time window). It is the gateway-plane counterpart to
// internal/langfuse, and is deliberately shaped the same way -- same Option
// pattern, same typed *Error, same backoff-with-jitter, same GetRaw-style
// method returning undecoded bytes -- so the two read side by side and
// cmd/wiretapd can treat a source failure identically regardless of which
// source produced it.
//
// # Why /spend/logs/v2 and not /spend/logs
//
// Both endpoints exist and both return spend records. /spend/logs is a
// trap: with no query parameters it returns every row in the table as a
// flat array, but the moment start_date/end_date are supplied it switches
// to returning *daily aggregates* -- a completely different shape, with no
// error and no warning. Adding a date filter to narrow a fetch would
// silently start returning objects like
// {"users":{...},"models":{...},"spend":0.001,"startTime":"2026-07-30"},
// which decode into an empty record rather than failing loudly.
//
// /spend/logs/v2 has exactly one response shape, always, and *requires*
// dates (answering a missing one with a 400 rather than a surprise). It
// also carries a real pagination envelope and server-side filtering. The
// endpoint that fails loudly on misuse is worth more here than the one
// that is convenient to call.
//
// # Authentication
//
// LiteLLM's admin API authenticates with the proxy master key as a bearer
// token. That key is the most privileged credential in this deployment --
// it can mint virtual keys, read every spend record, and change proxy
// configuration. It is set on exactly one line of this package
// (newRequest), is never included in any *Error, and nothing here logs
// request headers. See internal/litellm's TestError_NeverCarriesMasterKey.
package litellm

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultTimeout        = 30 * time.Second
	defaultUserAgent      = "wiretap-litellm-client"
	defaultMaxRetries     = 4
	defaultInitialBackoff = 500 * time.Millisecond
	defaultMaxBackoff     = 30 * time.Second
)

// Client is a LiteLLM proxy admin API client. Use New to construct one; the
// zero value is not usable (it has no base URL or credentials).
type Client struct {
	baseURL    string
	masterKey  string
	httpClient *http.Client
	userAgent  string

	maxRetries     int
	initialBackoff time.Duration
	maxBackoff     time.Duration
}

// Option configures a Client constructed by New.
type Option func(*Client)

// WithHTTPClient overrides the default *http.Client (30s timeout, otherwise
// stdlib defaults).
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithUserAgent overrides the default User-Agent header.
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// WithMaxRetries caps how many times a retryable failure (429, 5xx,
// transport error) is retried before giving up. 0 disables retrying.
func WithMaxRetries(n int) Option {
	return func(c *Client) { c.maxRetries = n }
}

// WithBackoff overrides the exponential backoff's starting delay and cap.
// Actual sleep is jittered within [d/2, d) each attempt; see sleepWithJitter.
func WithBackoff(initial, max time.Duration) Option {
	return func(c *Client) { c.initialBackoff = initial; c.maxBackoff = max }
}

// New returns a Client for the LiteLLM proxy at baseURL, authenticating
// with masterKey as a bearer token (LiteLLM's own convention for admin
// routes).
func New(baseURL, masterKey string, opts ...Option) *Client {
	c := &Client{
		baseURL:        strings.TrimRight(baseURL, "/"),
		masterKey:      masterKey,
		httpClient:     &http.Client{Timeout: defaultTimeout},
		userAgent:      defaultUserAgent,
		maxRetries:     defaultMaxRetries,
		initialBackoff: defaultInitialBackoff,
		maxBackoff:     defaultMaxBackoff,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values) (*http.Request, error) {
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return nil, fmt.Errorf("building URL: %w", err)
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	// The only place the master key is used. Never logged: nothing in this
	// package prints request headers, and *Error only ever carries the
	// response status/body, never the request we sent.
	req.Header.Set("Authorization", "Bearer "+c.masterKey)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// do sends req, retrying retryable failures (429, 5xx, transport errors)
// with capped exponential backoff and jitter, honouring a Retry-After
// header when the server sends one. It returns the response body already
// read into memory (the response's Body is always closed) and a typed
// *Error on any non-2xx status or transport failure. A GET request with a
// nil body -- the only kind this package sends -- can be safely re-issued
// on retry without cloning.
func (c *Client) do(ctx context.Context, req *http.Request) ([]byte, error) {
	backoff := c.initialBackoff

	for attempt := 0; ; attempt++ {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			transportErr := &Error{Kind: ErrTransport, Err: err}
			if attempt >= c.maxRetries {
				return nil, transportErr
			}
			if !sleepWithJitter(ctx, backoff) {
				return nil, ctx.Err()
			}
			backoff = nextBackoff(backoff, c.maxBackoff)
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			bodyErr := &Error{Kind: ErrTransport, Err: fmt.Errorf("reading response body: %w", readErr)}
			if attempt >= c.maxRetries {
				return nil, bodyErr
			}
			if !sleepWithJitter(ctx, backoff) {
				return nil, ctx.Err()
			}
			backoff = nextBackoff(backoff, c.maxBackoff)
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return body, nil
		}

		apiErr := classifyStatus(resp.StatusCode, resp.Status, body, resp.Header)
		if !apiErr.retryable() || attempt >= c.maxRetries {
			return nil, apiErr
		}

		wait := backoff
		if apiErr.RetryAfter > 0 {
			wait = apiErr.RetryAfter
		}
		if !sleepWithJitter(ctx, wait) {
			return nil, ctx.Err()
		}
		backoff = nextBackoff(backoff, c.maxBackoff)
	}
}

func nextBackoff(cur, max time.Duration) time.Duration {
	next := cur * 2
	if next > max {
		next = max
	}
	return next
}

// sleepWithJitter waits somewhere in [d/2, d), or returns false early if ctx
// is cancelled first. Full jitter would allow a wait of ~0, which defeats
// the point of backing off at all; halving the floor keeps every wait
// meaningfully longer than the last while still spreading retries out.
func sleepWithJitter(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	half := d / 2
	jittered := half + time.Duration(rand.Int64N(int64(half)+1))
	select {
	case <-ctx.Done():
		return false
	case <-time.After(jittered):
		return true
	}
}

// Ping confirms the spend API is reachable and that the master key is
// accepted, by asking for a single record over a deliberately tiny window.
//
// It queries the real endpoint rather than LiteLLM's /health/liveliness
// because liveliness requires no authentication: it answers 200 for a
// completely wrong master key, which makes it useless as a preflight for
// the one thing most likely to be misconfigured. A one-record query over a
// one-second window is cheap and actually exercises auth.
func (c *Client) Ping(ctx context.Context) error {
	now := time.Now().UTC()
	_, err := c.ListSpendLogs(ctx, ListParams{
		StartDate: now.Add(-time.Second),
		EndDate:   now,
		Page:      1,
		PageSize:  1,
	})
	return err
}
