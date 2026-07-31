package litellm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testMasterKey = "sk-master-DO-NOT-LOG-ME-abcdef123456"

// window is a valid, non-zero ListParams time range. Every call needs one:
// the API rejects a missing date, and so does ListParams.query.
func window() ListParams {
	return ListParams{
		StartDate: time.Date(2026, 7, 30, 23, 0, 0, 0, time.UTC),
		EndDate:   time.Date(2026, 7, 31, 23, 59, 59, 0, time.UTC),
	}
}

func testClient(t *testing.T, handler http.HandlerFunc, opts ...Option) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	allOpts := append([]Option{WithBackoff(1*time.Millisecond, 5*time.Millisecond)}, opts...)
	return New(srv.URL, testMasterKey, allOpts...)
}

func TestListSpendLogs_HappyPath(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/spend/logs/v2" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got, want := r.Header.Get("Authorization"), "Bearer "+testMasterKey; got != want {
			t.Errorf("Authorization = %q, want bearer master key", got)
		}
		w.Write([]byte(`{"data":[{"request_id":"r1"},{"request_id":"r2"}],"total":2,"page":1,"page_size":100,"total_pages":1,"total_is_capped":false}`))
	})

	page, err := c.ListSpendLogs(context.Background(), window())
	if err != nil {
		t.Fatalf("ListSpendLogs: %v", err)
	}
	if len(page.Data) != 2 {
		t.Errorf("expected 2 records, got %d", len(page.Data))
	}
	if page.Total != 2 || page.TotalPages != 1 {
		t.Errorf("unexpected pagination meta: %+v", page)
	}
	if page.HasMore() {
		t.Error("HasMore() = true on a 2-of-100 page, want false")
	}
}

// TestListSpendLogs_SendsLiteLLMDateFormatNotRFC3339 guards the single
// easiest thing to get wrong about this API. /spend/logs/v2 accepts
// "2006-01-02 15:04:05" and answers RFC3339 with a 400 -- verified against
// a live proxy. A client that formats dates the obvious Go way fails every
// call, so the format is pinned by a test rather than trusted to a
// constant nobody re-reads.
func TestListSpendLogs_SendsLiteLLMDateFormatNotRFC3339(t *testing.T) {
	var gotStart, gotEnd, gotSort, gotOrder string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		gotStart, gotEnd = q.Get("start_date"), q.Get("end_date")
		gotSort, gotOrder = q.Get("sort_by"), q.Get("sort_order")
		w.Write([]byte(`{"data":[],"total":0,"page":1,"page_size":100,"total_pages":1}`))
	})

	if _, err := c.ListSpendLogs(context.Background(), window()); err != nil {
		t.Fatalf("ListSpendLogs: %v", err)
	}

	if gotStart != "2026-07-30 23:00:00" {
		t.Errorf("start_date = %q, want %q", gotStart, "2026-07-30 23:00:00")
	}
	if gotEnd != "2026-07-31 23:59:59" {
		t.Errorf("end_date = %q, want %q", gotEnd, "2026-07-31 23:59:59")
	}
	for _, v := range []string{gotStart, gotEnd} {
		if strings.ContainsAny(v, "TZ") {
			t.Errorf("date %q looks like RFC3339; the API rejects that form with a 400", v)
		}
	}
	// Ascending startTime is what makes checkpointed fetching coherent.
	if gotSort != "startTime" || gotOrder != "asc" {
		t.Errorf("sort = %q/%q, want startTime/asc", gotSort, gotOrder)
	}
}

func TestListSpendLogs_MissingDatesIsBadRequestWithoutCallingServer(t *testing.T) {
	var calls int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Write([]byte(`{"data":[],"total":0,"page":1,"page_size":100}`))
	})

	_, err := c.ListSpendLogs(context.Background(), ListParams{})
	if !IsBadRequest(err) {
		t.Fatalf("expected IsBadRequest, got %v", err)
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("server was called %d times; a missing date should fail before the request", n)
	}
}

func TestListSpendLogs_PageSizeClampedToMax(t *testing.T) {
	var got string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("page_size")
		w.Write([]byte(`{"data":[],"total":0,"page":1,"page_size":100,"total_pages":1}`))
	})

	p := window()
	p.PageSize = 5000 // a live proxy answers this with a 422
	if _, err := c.ListSpendLogs(context.Background(), p); err != nil {
		t.Fatalf("ListSpendLogs: %v", err)
	}
	if got != "100" {
		t.Errorf("page_size = %q, want it clamped to 100", got)
	}
}

// TestListSpendLogs_WrongEndpointShapeIsDecodeError covers pointing this
// client at /spend/logs instead of /spend/logs/v2. That endpoint returns a
// bare array (or, with dates, daily aggregates) -- neither of which errors
// when decoded into the envelope struct; both produce a zero-valued page
// that a fetch loop would read as "no data, we're done".
func TestListSpendLogs_WrongEndpointShapeIsDecodeError(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"bare array (no dates)", `[{"request_id":"r1"}]`},
		{"daily aggregates (with dates)", `[{"users":{},"models":{},"spend":0.001,"startTime":"2026-07-30"}]`},
		{"empty object", `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			})
			_, err := c.ListSpendLogs(context.Background(), window())
			if err == nil {
				t.Fatal("expected an error for a response with no pagination envelope, got nil")
			}
			if kindOf(err) != ErrDecode {
				t.Errorf("kind = %v, want decode", kindOf(err))
			}
		})
	}
}

func TestListSpendLogs_AuthErrorIsNotRetried(t *testing.T) {
	var calls int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"message":"Authentication Error","type":"auth_error"}}`))
	})

	_, err := c.ListSpendLogs(context.Background(), window())
	if !IsAuthError(err) {
		t.Fatalf("expected IsAuthError, got %v", err)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("auth failure was retried %d times; retrying a rejected credential cannot help", n-1)
	}
}

// TestListSpendLogs_NotFoundIsDistinctFromAuth matters because a LiteLLM
// build without /spend/logs/v2 answers 404, and treating that as an auth
// problem would send someone rotating a perfectly good master key.
func TestListSpendLogs_NotFoundIsDistinctFromAuth(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"detail":"Not Found"}`))
	})

	_, err := c.ListSpendLogs(context.Background(), window())
	if !IsNotFound(err) {
		t.Fatalf("expected IsNotFound, got %v", err)
	}
	if IsAuthError(err) {
		t.Error("a 404 must not classify as an auth error")
	}
}

func TestListSpendLogs_RetriesRateLimitThenSucceeds(t *testing.T) {
	var calls int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"data":[{"request_id":"r1"}],"total":1,"page":1,"page_size":100,"total_pages":1}`))
	})

	page, err := c.ListSpendLogs(context.Background(), window())
	if err != nil {
		t.Fatalf("ListSpendLogs: %v", err)
	}
	if len(page.Data) != 1 {
		t.Errorf("expected 1 record after retries, got %d", len(page.Data))
	}
	if n := atomic.LoadInt32(&calls); n != 3 {
		t.Errorf("expected 3 attempts, got %d", n)
	}
}

func TestListSpendLogs_RateLimitedExhaustsRetries(t *testing.T) {
	var calls int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}, WithMaxRetries(2))

	_, err := c.ListSpendLogs(context.Background(), window())
	if !IsRateLimited(err) {
		t.Fatalf("expected IsRateLimited, got %v", err)
	}
	if n := atomic.LoadInt32(&calls); n != 3 { // initial + 2 retries
		t.Errorf("expected 3 attempts, got %d", n)
	}
}

func TestListSpendLogs_TransportErrorIsRetried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	c := New(url, testMasterKey, WithBackoff(1*time.Millisecond, 2*time.Millisecond), WithMaxRetries(2))
	_, err := c.ListSpendLogs(context.Background(), window())
	if !IsTransportError(err) {
		t.Fatalf("expected IsTransportError, got %v", err)
	}
}

// TestError_NeverCarriesMasterKey is the guard for this package's one
// genuinely dangerous value. The master key can mint virtual keys, read
// every spend record, and rewrite proxy config -- and an error string is
// exactly the kind of thing that ends up in a log aggregator, a ticket, or
// a screenshot. It must never appear in an error, a page, or anything else
// this package hands back to a caller.
func TestError_NeverCarriesMasterKey(t *testing.T) {
	// A server that maliciously echoes the caller's own credential back in
	// the response body -- the worst realistic case, since Error.Body is
	// populated from exactly that.
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"upstream said: ` + r.Header.Get("Authorization") + `"}`))
	}, WithMaxRetries(0))

	_, err := c.ListSpendLogs(context.Background(), window())
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), testMasterKey) {
		t.Errorf("Error() leaked the master key: %s", err.Error())
	}

	// Error.Body deliberately holds the response for diagnostics, so if a
	// server echoes the key it lands there. That is the server's doing, not
	// this package's -- what matters is that Error() (the thing that gets
	// logged) does not print Body.
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error is not a *litellm.Error: %T", err)
	}
	if strings.Contains(e.Error(), e.Body) && e.Body != "" {
		t.Error("Error() includes the raw response body; a server echoing the credential would leak it into logs")
	}
}

func TestPing_UsesAuthenticatedEndpointNotLiveliness(t *testing.T) {
	var path string
	var authed bool
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		authed = r.Header.Get("Authorization") != ""
		w.Write([]byte(`{"data":[],"total":0,"page":1,"page_size":1,"total_pages":1}`))
	})

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if path != "/spend/logs/v2" {
		t.Errorf("Ping hit %q; /health/liveliness needs no auth and would pass with a wrong master key", path)
	}
	if !authed {
		t.Error("Ping sent no Authorization header, so it cannot detect a bad master key")
	}
}

func TestPing_SurfacesAuthFailure(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	if err := c.Ping(context.Background()); !IsAuthError(err) {
		t.Fatalf("Ping with a bad key: got %v, want an auth error", err)
	}
}
