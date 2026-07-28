package esink

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func testIndexer(t *testing.T, handler http.HandlerFunc, opts ...BulkIndexerOption) *BulkIndexer {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := New(srv.URL)
	deadLetter := filepath.Join(t.TempDir(), "dead-letter.json")
	allOpts := append([]BulkIndexerOption{
		WithDeadLetterPath(deadLetter),
		WithBackoff(1*time.Millisecond, 5*time.Millisecond),
	}, opts...)
	return NewBulkIndexer(client, "wiretap-llm-events", allOpts...)
}

// TestBulkIndexer_CleanSuccess covers a _bulk call where every document is
// indexed without error.
func TestBulkIndexer_CleanSuccess(t *testing.T) {
	idx := testIndexer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_bulk" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		body, _ := readAll(r)
		lines := bytes.Count(body, []byte("\n"))
		if lines != 4 { // 2 docs x (action + source) lines
			t.Errorf("expected 4 NDJSON lines, got %d: %s", lines, body)
		}
		w.Write([]byte(`{"errors":false,"items":[{"index":{"_id":"a","status":201}},{"index":{"_id":"b","status":201}}]}`))
	})

	ctx := context.Background()
	if err := idx.Add(ctx, "a", map[string]string{"x": "1"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := idx.Add(ctx, "b", map[string]string{"x": "2"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := idx.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	c := idx.Counters()
	if c.Indexed != 2 || c.Failed != 0 || c.DeadLettered != 0 {
		t.Errorf("Counters = %+v, want Indexed=2 Failed=0 DeadLettered=0", c)
	}
}

// TestBulkIndexer_PartialFailureWithHTTP200 covers the case Elasticsearch
// is notorious for: the HTTP status is 200, but one item in the response
// body failed. A client that only checks the HTTP status would report
// success here and be wrong.
func TestBulkIndexer_PartialFailureWithHTTP200(t *testing.T) {
	idx := testIndexer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // the whole request "succeeded"
		w.Write([]byte(`{"errors":true,"items":[
			{"index":{"_id":"a","status":201}},
			{"index":{"_id":"b","status":400,"error":{"type":"mapper_parsing_exception","reason":"failed to parse field [event.duration]"}}}
		]}`))
	})

	ctx := context.Background()
	idx.Add(ctx, "a", map[string]string{"x": "1"})
	idx.Add(ctx, "b", map[string]string{"x": "bad"})
	if err := idx.Flush(ctx); err != nil {
		t.Fatalf("Flush returned an error for a partial failure that was handled (dead-lettered): %v", err)
	}

	c := idx.Counters()
	if c.Indexed != 1 {
		t.Errorf("Indexed = %d, want 1", c.Indexed)
	}
	if c.Failed != 1 || c.DeadLettered != 1 {
		t.Errorf("Failed/DeadLettered = %d/%d, want 1/1", c.Failed, c.DeadLettered)
	}
}

// TestBulkIndexer_429WithRetryAfterThenSucceeds covers a rate-limited whole
// request that succeeds once retried, honouring Retry-After.
func TestBulkIndexer_429WithRetryAfterThenSucceeds(t *testing.T) {
	var calls int32
	idx := testIndexer(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"errors":false,"items":[{"index":{"_id":"a","status":201}}]}`))
	}, WithMaxRetries(3))

	ctx := context.Background()
	idx.Add(ctx, "a", map[string]string{"x": "1"})
	if err := idx.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected 2 calls (1 rate-limited + 1 success), got %d", got)
	}
	c := idx.Counters()
	if c.Indexed != 1 || c.Retried != 1 {
		t.Errorf("Counters = %+v, want Indexed=1 Retried=1", c)
	}
}

// TestBulkIndexer_MappingConflictGoesToDeadLetterFile covers a permanent
// per-item failure (400 mapping conflict) landing in the dead-letter file
// with the full Elasticsearch error attached, and confirms it is not
// retried in a hot loop.
func TestBulkIndexer_MappingConflictGoesToDeadLetterFile(t *testing.T) {
	var calls int32
	idx := testIndexer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"errors":true,"items":[{"index":{"_id":"bad-doc","status":400,"error":{"type":"mapper_parsing_exception","reason":"object mapping for [llm] tried to parse field [llm] as object, but found a concrete value"}}}]}`))
	})

	ctx := context.Background()
	idx.Add(ctx, "bad-doc", map[string]string{"x": "bad"})
	if err := idx.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected exactly 1 call (no retry for a permanent 400), got %d", got)
	}

	data, err := os.ReadFile(idx.deadLetterPath)
	if err != nil {
		t.Fatalf("reading dead-letter file: %v", err)
	}
	var rec DeadLetterRecord
	if err := json.Unmarshal(bytes.TrimSpace(data), &rec); err != nil {
		t.Fatalf("parsing dead-letter record: %v\n%s", err, data)
	}
	if rec.ID != "bad-doc" {
		t.Errorf("DeadLetterRecord.ID = %q, want %q", rec.ID, "bad-doc")
	}
	if rec.Status != 400 {
		t.Errorf("DeadLetterRecord.Status = %d, want 400", rec.Status)
	}
	if !bytes.Contains([]byte(rec.Reason), []byte("mapper_parsing_exception")) {
		t.Errorf("DeadLetterRecord.Reason missing the ES error type: %q", rec.Reason)
	}
	var storedDoc map[string]string
	if err := json.Unmarshal(rec.Document, &storedDoc); err != nil || storedDoc["x"] != "bad" {
		t.Errorf("DeadLetterRecord.Document does not contain the original document: %s", rec.Document)
	}
}

func TestBulkIndexer_EmptyFlushIsNoop(t *testing.T) {
	idx := testIndexer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should be sent for an empty batch")
	})
	if err := idx.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

func TestBulkIndexer_AutoFlushesOnFullBatch(t *testing.T) {
	var calls int32
	idx := testIndexer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Write([]byte(`{"errors":false,"items":[{"index":{"_id":"a","status":201}},{"index":{"_id":"b","status":201}}]}`))
	}, WithBatchSize(2))

	ctx := context.Background()
	idx.Add(ctx, "a", map[string]string{"x": "1"})
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("flushed before batch was full: %d calls", got)
	}
	idx.Add(ctx, "b", map[string]string{"x": "2"}) // fills the batch of 2
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected auto-flush at batch size 2, got %d calls", got)
	}
}

func readAll(r *http.Request) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r.Body)
	return buf.Bytes(), err
}
