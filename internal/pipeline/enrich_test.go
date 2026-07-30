package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wiretap/internal/langfuse"
)

// detailHandler lets a test control exactly what GET /api/public/traces/{id}
// returns per ID: a status code and a body. Missing IDs 404.
type detailHandler struct {
	mu        sync.Mutex
	responses map[string]detailResponse
	calls     map[string]int
}

type detailResponse struct {
	status int
	body   string
}

func newDetailHandler() *detailHandler {
	return &detailHandler{responses: map[string]detailResponse{}, calls: map[string]int{}}
}

func (h *detailHandler) set(id string, status int, body string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.responses[id] = detailResponse{status: status, body: body}
}

func (h *detailHandler) callCount(id string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls[id]
}

func (h *detailHandler) serve(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/public/traces/")
	h.mu.Lock()
	h.calls[id]++
	resp, ok := h.responses[id]
	h.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"not found"}`))
		return
	}
	w.WriteHeader(resp.status)
	w.Write([]byte(resp.body))
}

// mockLangfuseServer builds an httptest server that answers both
// GET /api/public/traces (a fixed list response) and
// GET /api/public/traces/{id} (via detailHandler).
func mockLangfuseServer(t *testing.T, listBody string, detail *detailHandler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/public/traces" {
			w.Write([]byte(listBody))
			return
		}
		detail.serve(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestFetcher(t *testing.T, srv *httptest.Server, cfg FetchConfig) *Fetcher {
	t.Helper()
	dir := t.TempDir()
	if cfg.OutPath == "" {
		cfg.OutPath = filepath.Join(dir, "archive.ndjson")
	}
	if cfg.StatePath == "" {
		cfg.StatePath = filepath.Join(dir, "state.json")
	}
	client := langfuse.New(srv.URL, "pub", "sec", langfuse.WithBackoff(1*time.Millisecond, 5*time.Millisecond))
	f, err := NewFetcher(client, cfg)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func readArchiveLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("reading archive: %v", err)
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestFetcher_Enrich_ArchivesDetailNotList(t *testing.T) {
	listBody := `{"data":[{"id":"t1","timestamp":"2026-07-29T10:00:00.000Z","tags":[]}],"meta":{"page":1,"totalPages":1}}`
	detail := newDetailHandler()
	detail.set("t1", http.StatusOK, `{"id":"t1","timestamp":"2026-07-29T10:00:00.000Z","observations":[{"id":"o1","type":"GENERATION","model":"groq/llama","usage":{"input":10,"output":5,"total":15}}]}`)

	srv := mockLangfuseServer(t, listBody, detail)
	f := newTestFetcher(t, srv, FetchConfig{Enrich: true})

	emitted, skipped, err := f.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if emitted != 1 || skipped != 0 {
		t.Fatalf("emitted=%d skipped=%d, want 1/0", emitted, skipped)
	}

	lines := readArchiveLines(t, f.cfg.OutPath)
	if len(lines) != 1 {
		t.Fatalf("archive has %d lines, want 1", len(lines))
	}
	var archived map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &archived); err != nil {
		t.Fatalf("archived line is not valid JSON: %v", err)
	}
	if _, hasObs := archived["observations"]; !hasObs {
		t.Fatal("archived line has no \"observations\" -- the list-shaped record was archived, not the enriched detail")
	}
	obs, ok := archived["observations"].([]any)
	if !ok || len(obs) != 1 {
		t.Fatalf("archived observations = %v, want the detail-shaped full object array", archived["observations"])
	}

	c := f.EnrichCounters()
	if c.Attempted != 1 || c.Succeeded != 1 || c.Skipped != 0 || c.Failed != 0 {
		t.Errorf("EnrichCounters = %+v, want Attempted=1 Succeeded=1", c)
	}
}

func TestFetcher_Enrich_404IsSkippedNotArchivedAndRetriedNextPoll(t *testing.T) {
	listBody := `{"data":[
		{"id":"t1","timestamp":"2026-07-29T10:00:00.000Z","tags":[]},
		{"id":"t2","timestamp":"2026-07-29T10:00:01.000Z","tags":[]}
	],"meta":{"page":1,"totalPages":1}}`
	detail := newDetailHandler()
	detail.set("t1", http.StatusOK, `{"id":"t1","timestamp":"2026-07-29T10:00:00.000Z","observations":[]}`)
	// t2 deliberately left unset -> 404, simulating Langfuse's async
	// ingestion race: the trace is in the list but detail isn't ready yet.

	srv := mockLangfuseServer(t, listBody, detail)
	f := newTestFetcher(t, srv, FetchConfig{Enrich: true})

	emitted, _, err := f.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if emitted != 1 {
		t.Fatalf("emitted = %d, want 1 (only t1)", emitted)
	}

	lines := readArchiveLines(t, f.cfg.OutPath)
	if len(lines) != 1 {
		t.Fatalf("archive has %d lines, want 1 (t2 must not be archived at all)", len(lines))
	}
	if strings.Contains(lines[0], `"t2"`) {
		t.Error("t2 appears in the archive despite its detail fetch 404ing")
	}

	c := f.EnrichCounters()
	if c.Skipped != 1 {
		t.Errorf("EnrichCounters.Skipped = %d, want 1", c.Skipped)
	}

	// Now let t2 become available (the race resolved) and poll again --
	// it must not have been marked seen, so it's retried.
	detail.set("t2", http.StatusOK, `{"id":"t2","timestamp":"2026-07-29T10:00:01.000Z","observations":[]}`)
	if err := f.SaveCheckpoint(); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}

	emitted, _, err = f.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce (2): %v", err)
	}
	if emitted != 1 {
		t.Fatalf("PollOnce (2) emitted = %d, want 1 (t2, now retried)", emitted)
	}

	lines = readArchiveLines(t, f.cfg.OutPath)
	if len(lines) != 2 {
		t.Fatalf("archive has %d lines after retry, want 2", len(lines))
	}
}

func TestFetcher_Enrich_AuthErrorAbortsPollWithNothingWritten(t *testing.T) {
	listBody := `{"data":[
		{"id":"t1","timestamp":"2026-07-29T10:00:00.000Z","tags":[]},
		{"id":"t2","timestamp":"2026-07-29T10:00:01.000Z","tags":[]}
	],"meta":{"page":1,"totalPages":1}}`
	detail := newDetailHandler()
	detail.set("t1", http.StatusOK, `{"id":"t1","timestamp":"2026-07-29T10:00:00.000Z","observations":[]}`)
	detail.set("t2", http.StatusUnauthorized, `{"message":"unauthorized"}`)

	srv := mockLangfuseServer(t, listBody, detail)
	f := newTestFetcher(t, srv, FetchConfig{Enrich: true})

	_, _, err := f.PollOnce(context.Background())
	if err == nil {
		t.Fatal("expected an error from a fatal (auth) enrichment failure")
	}

	lines := readArchiveLines(t, f.cfg.OutPath)
	if len(lines) != 0 {
		t.Fatalf("archive has %d lines, want 0 -- a fatal enrichment error must not write a partial page", len(lines))
	}
}

func TestFetcher_Enrich_BoundedConcurrency(t *testing.T) {
	const n = 12
	const limit = 3

	var itemsJSON strings.Builder
	itemsJSON.WriteString(`{"data":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			itemsJSON.WriteString(",")
		}
		fmt.Fprintf(&itemsJSON, `{"id":"t%d","timestamp":"2026-07-29T10:00:%02d.000Z","tags":[]}`, i, i)
	}
	itemsJSON.WriteString(`],"meta":{"page":1,"totalPages":1}}`)

	var inFlight, maxInFlight atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/public/traces" {
			w.Write([]byte(itemsJSON.String()))
			return
		}
		cur := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			m := maxInFlight.Load()
			if cur <= m || maxInFlight.CompareAndSwap(m, cur) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		id := strings.TrimPrefix(r.URL.Path, "/api/public/traces/")
		fmt.Fprintf(w, `{"id":%q,"timestamp":"2026-07-29T10:00:00.000Z","observations":[]}`, id)
	}))
	t.Cleanup(srv.Close)

	f := newTestFetcher(t, srv, FetchConfig{Enrich: true, EnrichConcurrency: limit})

	emitted, _, err := f.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if emitted != n {
		t.Fatalf("emitted = %d, want %d", emitted, n)
	}
	if got := maxInFlight.Load(); got > limit {
		t.Errorf("max concurrent detail fetches = %d, want <= %d", got, limit)
	}
	t.Logf("observed max concurrency: %d (limit %d)", maxInFlight.Load(), limit)
}

func TestFetcher_Enrich_Disabled_ArchivesListShapeUnchanged(t *testing.T) {
	listBody := `{"data":[{"id":"t1","timestamp":"2026-07-29T10:00:00.000Z","tags":[]}],"meta":{"page":1,"totalPages":1}}`
	detail := newDetailHandler() // never configured -- if this gets called, the test should fail

	srv := mockLangfuseServer(t, listBody, detail)
	f := newTestFetcher(t, srv, FetchConfig{Enrich: false})

	emitted, _, err := f.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if emitted != 1 {
		t.Fatalf("emitted = %d, want 1", emitted)
	}
	if detail.callCount("t1") != 0 {
		t.Error("GetTrace was called even though Enrich=false")
	}

	lines := readArchiveLines(t, f.cfg.OutPath)
	if len(lines) != 1 || strings.Contains(lines[0], "observations") {
		t.Errorf("archived line = %q, want the bare list-shaped record with no observations field", lines)
	}
}
