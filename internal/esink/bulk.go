package esink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultBatchSize      = 100
	defaultMaxRetries     = 4
	defaultInitialBackoff = 500 * time.Millisecond
	defaultMaxBackoff     = 30 * time.Second
	defaultDeadLetterFile = "dead-letter.json"
)

// bulkItem is one document queued for indexing.
type bulkItem struct {
	id  string
	doc json.RawMessage
}

// Counters is a point-in-time snapshot of a BulkIndexer's activity.
type Counters struct {
	Attempted    int64
	Indexed      int64
	Failed       int64
	Retried      int64
	DeadLettered int64
}

// BulkIndexerOption configures a BulkIndexer constructed by NewBulkIndexer.
type BulkIndexerOption func(*BulkIndexer)

// WithBatchSize sets how many documents Add buffers before triggering an
// automatic Flush.
func WithBatchSize(n int) BulkIndexerOption {
	return func(b *BulkIndexer) { b.batchSize = n }
}

// WithMaxRetries caps how many times a batch containing retryable failures
// (429, 503, transport errors) is retried before its remaining items are
// dead-lettered instead.
func WithMaxRetries(n int) BulkIndexerOption {
	return func(b *BulkIndexer) { b.maxRetries = n }
}

// WithDeadLetterPath overrides where permanently-failed documents are
// written (default "dead-letter.json", an NDJSON file despite the
// extension -- see DeadLetterRecord).
func WithDeadLetterPath(path string) BulkIndexerOption {
	return func(b *BulkIndexer) { b.deadLetterPath = path }
}

// WithBackoff overrides the exponential backoff's starting delay and cap
// used between retries of a retryable failure.
func WithBackoff(initial, max time.Duration) BulkIndexerOption {
	return func(b *BulkIndexer) { b.initialBackoff = initial; b.maxBackoff = max }
}

// BulkIndexer batches documents and ships them to Elasticsearch's _bulk
// API, using the trace ID as each document's _id so re-indexing the same
// event twice is a no-op overwrite rather than a duplicate (see arch.md for
// why that idempotency, not data-stream ergonomics, drove the "regular
// index + alias" choice over a data stream).
//
// It does not own a background flush timer: WithBatchSize triggers an
// automatic flush when the buffer fills, but time-based flushing (so a
// slow trickle of documents doesn't sit unflushed indefinitely) is the
// caller's responsibility -- call Flush on your own ticker. Keeping the
// timer out of this package makes it possible to test deterministically,
// and cmd/wiretapd already needs its own ticker for periodic counter
// logging, so it isn't extra work for that caller.
type BulkIndexer struct {
	client *Client
	index  string // the alias to index through

	batchSize      int
	maxRetries     int
	initialBackoff time.Duration
	maxBackoff     time.Duration
	deadLetterPath string

	mu    sync.Mutex
	batch []bulkItem

	attempted, indexed, failed, retried, deadLettered atomic.Int64
}

// NewBulkIndexer returns a BulkIndexer that indexes through the given
// alias.
func NewBulkIndexer(client *Client, index string, opts ...BulkIndexerOption) *BulkIndexer {
	b := &BulkIndexer{
		client:         client,
		index:          index,
		batchSize:      defaultBatchSize,
		maxRetries:     defaultMaxRetries,
		initialBackoff: defaultInitialBackoff,
		maxBackoff:     defaultMaxBackoff,
		deadLetterPath: defaultDeadLetterFile,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// Add queues doc (any JSON-marshalable value -- normally *ecs.Document) for
// indexing under _id id, flushing automatically if this fills the batch.
func (b *BulkIndexer) Add(ctx context.Context, id string, doc any) error {
	encoded, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshaling document %q: %w", id, err)
	}

	b.mu.Lock()
	b.batch = append(b.batch, bulkItem{id: id, doc: encoded})
	full := len(b.batch) >= b.batchSize
	b.mu.Unlock()

	if full {
		return b.Flush(ctx)
	}
	return nil
}

// Flush ships every currently-queued document and blocks until they're all
// either indexed, dead-lettered, or (if ctx is cancelled mid-retry)
// abandoned in the queue for a future Flush to pick up again.
func (b *BulkIndexer) Flush(ctx context.Context) error {
	b.mu.Lock()
	items := b.batch
	b.batch = nil
	b.mu.Unlock()

	if len(items) == 0 {
		return nil
	}
	return b.sendWithRetry(ctx, items, 0)
}

// Close flushes any remaining buffered documents. Safe to call even if
// Flush was just called and the batch is empty.
func (b *BulkIndexer) Close(ctx context.Context) error {
	return b.Flush(ctx)
}

// Counters returns a snapshot of this indexer's activity so far.
func (b *BulkIndexer) Counters() Counters {
	return Counters{
		Attempted:    b.attempted.Load(),
		Indexed:      b.indexed.Load(),
		Failed:       b.failed.Load(),
		Retried:      b.retried.Load(),
		DeadLettered: b.deadLettered.Load(),
	}
}

func (b *BulkIndexer) sendWithRetry(ctx context.Context, items []bulkItem, attempt int) error {
	b.attempted.Add(int64(len(items)))

	body := encodeBulkBody(b.index, items)
	respBody, err := b.client.do(ctx, http.MethodPost, "/_bulk", "application/x-ndjson", body)

	if err != nil {
		var esErr *Error
		if errors.As(err, &esErr) && esErr.retryable() && attempt < b.maxRetries {
			b.retried.Add(int64(len(items)))
			wait := b.backoffFor(attempt)
			if esErr.RetryAfter > 0 {
				wait = esErr.RetryAfter
			}
			if !sleepWithJitter(ctx, wait) {
				// Put the items back so a future Flush retries them,
				// rather than silently losing them to a cancelled context.
				b.requeue(items)
				return ctx.Err()
			}
			return b.sendWithRetry(ctx, items, attempt+1)
		}
		b.failed.Add(int64(len(items)))
		return b.deadLetterAll(items, err.Error(), 0)
	}

	var parsed bulkResponse
	if jsonErr := json.Unmarshal(respBody, &parsed); jsonErr != nil {
		b.failed.Add(int64(len(items)))
		return b.deadLetterAll(items, fmt.Sprintf("parsing bulk response: %v", jsonErr), 0)
	}

	if !parsed.Errors {
		b.indexed.Add(int64(len(items)))
		return nil
	}

	return b.handlePartialFailure(ctx, items, parsed, attempt)
}

// handlePartialFailure is reached when Elasticsearch answered the bulk
// request with HTTP 200 but its own "errors" flag is true -- the single
// most common way a naive bulk client silently lies about success, since a
// 200 alone says nothing about whether any individual document made it in.
func (b *BulkIndexer) handlePartialFailure(ctx context.Context, items []bulkItem, parsed bulkResponse, attempt int) error {
	var retryItems []bulkItem
	var deadLetterErr error

	for i, result := range parsed.Items {
		action := result.Index
		if action == nil {
			// Not an index-action result (shouldn't happen -- every
			// request we send is an index action); treat conservatively
			// as a permanent per-item failure rather than guessing.
			b.failed.Add(1)
			if err := b.deadLetterOne(items[i], "bulk response item missing \"index\" result", 0); err != nil {
				deadLetterErr = err
			}
			continue
		}
		if action.Status >= 200 && action.Status < 300 {
			b.indexed.Add(1)
			continue
		}
		if isRetryableStatus(action.Status) && attempt < b.maxRetries {
			retryItems = append(retryItems, items[i])
			continue
		}
		b.failed.Add(1)
		reason := "unknown error"
		if action.Error != nil {
			reason = fmt.Sprintf("%s: %s", action.Error.Type, action.Error.Reason)
		}
		if err := b.deadLetterOne(items[i], reason, action.Status); err != nil {
			deadLetterErr = err
		}
	}

	if len(retryItems) > 0 {
		b.retried.Add(int64(len(retryItems)))
		if !sleepWithJitter(ctx, b.backoffFor(attempt)) {
			b.requeue(retryItems)
			return ctx.Err()
		}
		if err := b.sendWithRetry(ctx, retryItems, attempt+1); err != nil {
			return err
		}
	}
	return deadLetterErr
}

func isRetryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
}

func (b *BulkIndexer) requeue(items []bulkItem) {
	b.mu.Lock()
	b.batch = append(items, b.batch...)
	b.mu.Unlock()
}

func (b *BulkIndexer) backoffFor(attempt int) time.Duration {
	d := b.initialBackoff
	for i := 0; i < attempt; i++ {
		d *= 2
		if d > b.maxBackoff {
			return b.maxBackoff
		}
	}
	return d
}

// sleepWithJitter waits somewhere in [d/2, d), or returns false early if
// ctx is cancelled first.
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

// DeadLetterRecord is one line of the dead-letter file: a permanently
// failed document, its Elasticsearch error, and enough context to decide
// by hand whether to fix and replay it.
type DeadLetterRecord struct {
	Timestamp time.Time       `json:"timestamp"`
	ID        string          `json:"id"`
	Status    int             `json:"status"`
	Reason    string          `json:"reason"`
	Document  json.RawMessage `json:"document"`
}

func (b *BulkIndexer) deadLetterAll(items []bulkItem, reason string, status int) error {
	var firstErr error
	for _, it := range items {
		if err := b.deadLetterOne(it, reason, status); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (b *BulkIndexer) deadLetterOne(item bulkItem, reason string, status int) error {
	b.deadLettered.Add(1)
	rec := DeadLetterRecord{
		Timestamp: time.Now().UTC(),
		ID:        item.id,
		Status:    status,
		Reason:    reason,
		Document:  item.doc,
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encoding dead-letter record for %q: %w", item.id, err)
	}
	f, err := os.OpenFile(b.deadLetterPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening dead-letter file %q: %w", b.deadLetterPath, err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("writing dead-letter file %q: %w", b.deadLetterPath, err)
	}
	return nil
}

// bulkResponse mirrors the subset of Elasticsearch's _bulk response this
// package needs. Per Elasticsearch's own semantics, the HTTP status of a
// _bulk request is 200 even when individual items failed -- Errors is the
// field that actually says so, and Items[i].Index.Status is what actually
// says which one.
type bulkResponse struct {
	Errors bool `json:"errors"`
	Items  []struct {
		Index *bulkItemResult `json:"index"`
	} `json:"items"`
}

type bulkItemResult struct {
	ID     string `json:"_id"`
	Status int    `json:"status"`
	Error  *struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	} `json:"error"`
}

// encodeBulkBody builds the NDJSON body _bulk expects: one action line
// (naming the target index/_id) followed by one source line, per document.
func encodeBulkBody(index string, items []bulkItem) []byte {
	var buf bytes.Buffer
	for _, it := range items {
		action, _ := json.Marshal(map[string]any{
			"index": map[string]any{"_index": index, "_id": it.id},
		})
		buf.Write(action)
		buf.WriteByte('\n')
		buf.Write(it.doc)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}
