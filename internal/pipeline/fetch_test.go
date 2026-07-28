package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"wiretap/internal/langfuse"
)

func TestFetcher_PollOnceWritesArchiveAndDedupsOnRepoll(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			w.Write([]byte(`{"data":[{"id":"t1","timestamp":"2026-07-29T10:00:00.000Z","tags":["wiretap","benign"]}],"meta":{"page":1,"totalPages":1}}`))
			return
		}
		// Second poll: same trace still comes back from the API (it's
		// within the overlap window), but must not be re-written.
		w.Write([]byte(`{"data":[{"id":"t1","timestamp":"2026-07-29T10:00:00.000Z","tags":["wiretap","benign"]}],"meta":{"page":1,"totalPages":1}}`))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	cfg := FetchConfig{
		OutPath:   filepath.Join(dir, "archive.ndjson"),
		StatePath: filepath.Join(dir, "state.json"),
	}
	client := langfuse.New(srv.URL, "pub", "sec")
	f, err := NewFetcher(client, cfg)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	defer f.Close()

	ctx := context.Background()
	emitted, skipped, err := f.PollOnce(ctx)
	if err != nil {
		t.Fatalf("PollOnce (1): %v", err)
	}
	if emitted != 1 || skipped != 0 {
		t.Fatalf("PollOnce (1) = emitted=%d skipped=%d, want 1/0", emitted, skipped)
	}
	if err := f.SaveCheckpoint(); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}

	emitted, skipped, err = f.PollOnce(ctx)
	if err != nil {
		t.Fatalf("PollOnce (2): %v", err)
	}
	if emitted != 0 {
		t.Errorf("PollOnce (2) emitted=%d, want 0 (already seen)", emitted)
	}

	data, err := os.ReadFile(cfg.OutPath)
	if err != nil {
		t.Fatalf("reading archive: %v", err)
	}
	if got := countLines(data); got != 1 {
		t.Errorf("archive has %d lines, want 1 (no duplicate write)", got)
	}

	if _, err := os.Stat(cfg.StatePath); err != nil {
		t.Errorf("checkpoint file was not written: %v", err)
	}
}

func TestFetcher_SkipHealthchecks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[
			{"id":"hc1","timestamp":"2026-07-29T10:00:00.000Z","tags":["litellm-internal-health-check"]},
			{"id":"t1","timestamp":"2026-07-29T10:00:01.000Z","tags":["wiretap","benign"]}
		],"meta":{"page":1,"totalPages":1}}`))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	cfg := FetchConfig{
		OutPath:          filepath.Join(dir, "archive.ndjson"),
		StatePath:        filepath.Join(dir, "state.json"),
		SkipHealthchecks: true,
	}
	client := langfuse.New(srv.URL, "pub", "sec")
	f, err := NewFetcher(client, cfg)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	defer f.Close()

	emitted, skipped, err := f.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if emitted != 1 || skipped != 1 {
		t.Fatalf("PollOnce = emitted=%d skipped=%d, want 1/1", emitted, skipped)
	}
}

func countLines(data []byte) int {
	n := 0
	for _, b := range data {
		if b == '\n' {
			n++
		}
	}
	return n
}
