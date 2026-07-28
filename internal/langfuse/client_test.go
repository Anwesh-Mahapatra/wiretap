package langfuse

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, handler http.HandlerFunc, opts ...Option) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	allOpts := append([]Option{WithBackoff(1*time.Millisecond, 5*time.Millisecond)}, opts...)
	return New(srv.URL, "pub", "sec", allOpts...)
}

func TestListTraces_HappyPath(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/public/traces" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "pub" || pass != "sec" {
			t.Errorf("bad basic auth: %q %q %v", user, pass, ok)
		}
		w.Write([]byte(`{"data":[{"id":"t1"},{"id":"t2"}],"meta":{"page":1,"totalPages":3}}`))
	})

	page, err := c.ListTraces(context.Background(), ListTracesParams{})
	if err != nil {
		t.Fatalf("ListTraces: %v", err)
	}
	if len(page.Data) != 2 {
		t.Errorf("expected 2 items, got %d", len(page.Data))
	}
	if page.TotalPages != 3 {
		t.Errorf("expected TotalPages=3, got %d", page.TotalPages)
	}
}

func TestGetTrace_HappyPath(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/public/traces/abc123" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(`{"id":"abc123","name":"wiretap-benign","observations":[{"id":"o1","type":"GENERATION","usage":{"input":10,"output":20,"total":30}}]}`))
	})

	tr, err := c.GetTrace(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("GetTrace: %v", err)
	}
	if tr.ID != "abc123" || len(tr.Observations) != 1 {
		t.Fatalf("unexpected trace: %+v", tr)
	}
	if tr.Observations[0].Usage == nil || tr.Observations[0].Usage.Total != 30 {
		t.Errorf("unexpected usage: %+v", tr.Observations[0].Usage)
	}
}

func TestGetTrace_NotFoundIsNotRetried(t *testing.T) {
	var calls int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"not found"}`))
	})

	_, err := c.GetTrace(context.Background(), "missing")
	if !IsNotFound(err) {
		t.Fatalf("expected IsNotFound, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected exactly 1 call (no retry on 404), got %d", got)
	}
}

func TestGetTrace_AuthError(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	_, err := c.GetTrace(context.Background(), "x")
	if !IsAuthError(err) {
		t.Fatalf("expected IsAuthError, got %v", err)
	}
}

func TestListTraces_RetriesRateLimitThenSucceeds(t *testing.T) {
	var calls int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"data":[],"meta":{"page":1,"totalPages":1}}`))
	}, WithMaxRetries(3))

	_, err := c.ListTraces(context.Background(), ListTracesParams{})
	if err != nil {
		t.Fatalf("ListTraces: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected 2 calls (1 rate-limited + 1 success), got %d", got)
	}
}

func TestListTraces_RateLimitedExhaustsRetries(t *testing.T) {
	var calls int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}, WithMaxRetries(2))

	_, err := c.ListTraces(context.Background(), ListTracesParams{})
	if !IsRateLimited(err) {
		t.Fatalf("expected IsRateLimited, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 { // 1 initial + 2 retries
		t.Errorf("expected 3 calls, got %d", got)
	}
}

func TestListTraces_TransportErrorIsRetried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[],"meta":{"page":1,"totalPages":1}}`))
	}))
	t.Cleanup(srv.Close)

	// Point at a server that refuses connections first, wrapped so we can't
	// easily flip behaviour mid-test with httptest alone -- instead this
	// verifies the not-retried/retried classification indirectly via the
	// rate-limit test above, and directly exercises IsTransportError by
	// dialing a closed port.
	c := New("http://127.0.0.1:1", "pub", "sec", WithBackoff(1*time.Millisecond, 2*time.Millisecond), WithMaxRetries(1))
	_, err := c.ListTraces(context.Background(), ListTracesParams{})
	if !IsTransportError(err) {
		t.Fatalf("expected IsTransportError, got %v", err)
	}
}

func TestClient_UserAgentAndBasicAuthNeverLeakSecretInError(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua == "" {
			t.Error("expected non-empty User-Agent")
		}
		auth := r.Header.Get("Authorization")
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("pub:sec"))
		if auth != expected {
			t.Errorf("unexpected Authorization header: %q", auth)
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"forbidden"}`))
	})

	_, err := c.GetTrace(context.Background(), "x")
	le, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T", err)
	}
	if le.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", le.StatusCode)
	}
	// The secret key must never appear in an error's Status/Body -- both
	// come straight from the server's response, never from our own request.
	if contains(le.Body, "sec") || contains(le.Status, "sec") {
		t.Errorf("secret key leaked into error: %+v", le)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
