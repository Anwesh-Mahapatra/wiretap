package esink

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestBootstrap_IdempotentSecondRunDoesNotError simulates the index
// existing on the second call (via HEAD returning 404 then 200) and
// confirms Bootstrap succeeds both times without attempting to re-create
// an existing index.
func TestBootstrap_IdempotentSecondRunDoesNotError(t *testing.T) {
	var templatePuts, indexExistsChecks, indexCreates int32
	indexCreated := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/_index_template/wiretap-llm-events-template":
			atomic.AddInt32(&templatePuts, 1)
			w.Write([]byte(`{"acknowledged":true}`))
		case r.Method == http.MethodHead && r.URL.Path == "/wiretap-llm-events-000001":
			atomic.AddInt32(&indexExistsChecks, 1)
			if indexCreated {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case r.Method == http.MethodPut && r.URL.Path == "/wiretap-llm-events-000001":
			atomic.AddInt32(&indexCreates, 1)
			indexCreated = true
			w.Write([]byte(`{"acknowledged":true,"shards_acknowledged":true,"index":"wiretap-llm-events-000001"}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	client := New(srv.URL)
	cfg := BootstrapConfig{IndexBase: "wiretap-llm-events"}

	if err := client.Bootstrap(context.Background(), cfg); err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}
	if err := client.Bootstrap(context.Background(), cfg); err != nil {
		t.Fatalf("second Bootstrap (must be idempotent): %v", err)
	}

	if got := atomic.LoadInt32(&templatePuts); got != 2 {
		t.Errorf("templatePuts = %d, want 2 (PUT is itself idempotent, called every run)", got)
	}
	if got := atomic.LoadInt32(&indexCreates); got != 1 {
		t.Errorf("indexCreates = %d, want 1 (second run must skip creation)", got)
	}
	if got := atomic.LoadInt32(&indexExistsChecks); got != 2 {
		t.Errorf("indexExistsChecks = %d, want 2", got)
	}
}
