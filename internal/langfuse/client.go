// Package langfuse is a minimal client for the subset of Langfuse's public
// API wiretap needs: listing traces (paginated, filterable by timestamp) and
// fetching one trace's full detail (including its observations). It exists
// so tracepump, tracescope, and wiretapd's fetch stage don't each carry
// their own copy of the same HTTP plumbing, retry logic, and error
// handling.
package langfuse

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
	defaultUserAgent      = "wiretap-langfuse-client"
	defaultMaxRetries     = 4
	defaultInitialBackoff = 500 * time.Millisecond
	defaultMaxBackoff     = 30 * time.Second
)

// Client is a Langfuse public API client. Use New to construct one; the
// zero value is not usable (it has no base URL or credentials).
type Client struct {
	baseURL    string
	publicKey  string
	secretKey  string
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

// New returns a Client for the Langfuse instance at baseURL, authenticating
// with publicKey/secretKey via HTTP Basic Auth (Langfuse's own convention).
func New(baseURL, publicKey, secretKey string, opts ...Option) *Client {
	c := &Client{
		baseURL:        strings.TrimRight(baseURL, "/"),
		publicKey:      publicKey,
		secretKey:      secretKey,
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
	// Basic Auth, not Bearer -- this is Langfuse's own convention (public
	// key as username, secret key as password). Never logged: nothing in
	// this package prints request headers, and *Error only ever carries the
	// response status/body, never the request we sent.
	req.SetBasicAuth(c.publicKey, c.secretKey)
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
