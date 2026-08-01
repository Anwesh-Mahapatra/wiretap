package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"wiretap/internal/litellm"
)

// The records below are shaped like real /spend/logs/v2 rows, cut down to
// the fields the fetch stage decodes. hcTagged and hcServiceAccount carry
// one each of the two independent stamps LiteLLM puts on its own health
// checks; production relies on either one being sufficient, so they are
// exercised separately. See gatewayRecordCore.isHealthCheck.
const (
	hcStartTime = "2026-08-01T00:16:31.534+00:00"

	hcTagged = `{"request_id":"hc1","startTime":"` + hcStartTime + `",` +
		`"request_tags":["litellm-internal-health-check"],"metadata":{}}`
	hcServiceAccount = `{"request_id":"hc2","startTime":"2026-08-01T00:16:32.000+00:00",` +
		`"api_key":"litellm-internal-health-check","metadata":` +
		`{"user_api_key_alias":"litellm-internal-health-check"}}`
	callerTraffic = `{"request_id":"chatcmpl-r1","startTime":"2026-08-01T00:16:33.000+00:00",` +
		`"request_tags":["wiretap","benign"],"api_key":"deadbeef","metadata":` +
		`{"spend_logs_metadata":{"trace_id":"benign-1"},"user_api_key_alias":"wiretap-main"}}`
)

// spendLogPage wraps records in the envelope /spend/logs/v2 returns. The
// page_size matters: litellm.SpendLogPage.HasMore stops on a short page,
// so a page_size larger than the record count is what ends the fetch loop.
func spendLogPage(records ...string) string {
	return `{"data":[` + strings.Join(records, ",") +
		`],"total":` + strconv.Itoa(len(records)) +
		`,"page":1,"page_size":100,"total_pages":1}`
}

// newGatewayFetcherForTest serves one fixed page from a stub proxy. From is
// always set so the checkpoint's first-run cutoff is a fixed instant rather
// than 24 hours before whenever the test happens to run.
func newGatewayFetcherForTest(t *testing.T, cfg GatewayFetchConfig, records ...string) *GatewayFetcher {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(spendLogPage(records...)))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	if cfg.OutPath == "" {
		cfg.OutPath = filepath.Join(dir, "spend.ndjson")
	}
	if cfg.StatePath == "" {
		cfg.StatePath = filepath.Join(dir, "gw-state.json")
	}
	cfg.From = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	f, err := NewGatewayFetcher(litellm.New(srv.URL, "master"), cfg)
	if err != nil {
		t.Fatalf("NewGatewayFetcher: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// TestGatewayFetcher_SkipHealthchecks is the gateway-plane twin of
// TestFetcher_SkipHealthchecks: LiteLLM's own health-check rows never
// reach the archive, and real caller traffic in the same page is
// unaffected.
func TestGatewayFetcher_SkipHealthchecks(t *testing.T) {
	cfg := GatewayFetchConfig{SkipHealthchecks: true}
	f := newGatewayFetcherForTest(t, cfg, hcTagged, hcServiceAccount, callerTraffic)

	emitted, skipped, err := f.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if emitted != 1 || skipped != 2 {
		t.Fatalf("PollOnce = emitted=%d skipped=%d, want 1/2 (both stamps recognised)", emitted, skipped)
	}

	data, err := os.ReadFile(f.cfg.OutPath)
	if err != nil {
		t.Fatalf("reading archive: %v", err)
	}
	if strings.Contains(string(data), "litellm-internal-health-check") {
		t.Error("archive contains a health-check record, want it dropped before it reached the archive")
	}
	if got := countLines(data); got != 1 {
		t.Errorf("archive has %d lines, want 1", got)
	}
}

// TestGatewayFetcher_HealthchecksArchivedWhenFlagOff is the other half of
// "honours the same flag": the filter is opt-in on both planes, and with
// it off the archive stays a faithful record of everything the API
// returned.
func TestGatewayFetcher_HealthchecksArchivedWhenFlagOff(t *testing.T) {
	f := newGatewayFetcherForTest(t, GatewayFetchConfig{}, hcTagged)

	emitted, _, err := f.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if emitted != 1 {
		t.Fatalf("PollOnce emitted=%d, want 1 -- the filter is opt-in", emitted)
	}
}

// TestGatewayFetcher_SkippedHealthcheckStillAdvancesCheckpoint covers the
// quiet-period case: a window carrying nothing but health checks must
// still move the cutoff forward and must not re-offer the same rows on
// every subsequent poll, the same way the content plane's fetcher marks a
// skipped health-check trace seen.
func TestGatewayFetcher_SkippedHealthcheckStillAdvancesCheckpoint(t *testing.T) {
	f := newGatewayFetcherForTest(t, GatewayFetchConfig{SkipHealthchecks: true}, hcTagged)

	if _, skipped, err := f.PollOnce(context.Background()); err != nil || skipped != 1 {
		t.Fatalf("PollOnce = skipped=%d err=%v, want 1/nil", skipped, err)
	}

	if len(f.cp.Seen) != 1 || f.cp.Seen[0].RequestID != "hc1" {
		t.Errorf("checkpoint Seen = %+v, want the skipped health check recorded so it is not reconsidered on every poll", f.cp.Seen)
	}

	start, err := time.Parse(time.RFC3339Nano, hcStartTime)
	if err != nil {
		t.Fatal(err)
	}
	want := start.UTC().Add(-gatewayOverlapWindow)
	if !f.cp.Cutoff.Equal(want) {
		t.Errorf("checkpoint Cutoff = %v, want %v -- a window of only health checks must not stall the checkpoint", f.cp.Cutoff, want)
	}
}
