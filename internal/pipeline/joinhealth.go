package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"wiretap/internal/esink"
)

// Join-health timing. These three numbers decide whether the metric is
// trustworthy, so they are derived and documented rather than picked.
//
// The metric asks "does every content event in this window have a gateway
// partner, and vice versa". If the window includes events that have not
// finished arriving yet, the answer is "no" for reasons that have nothing
// to do with the join -- and a metric that cries wolf about normal
// ingestion skew gets ignored within a week, which is worse than not
// having it at all.
//
// The full path from "request happens" to "document is queryable" is:
//
//	source-side visibility  +  our fetch interval  +  our index interval
//
// Source-side visibility, measured on this deployment (n=3 requests,
// 2026-08-01):
//
//	Langfuse trace queryable        6.78s – 7.19s
//	Langfuse observations complete  +0.04s after the trace (not a separate wait)
//	LiteLLM spend row queryable     7.04s – 7.68s
//
// Both planes land in about the same 7 seconds, so neither dominates.
// The measured figures are not the bound, though: LiteLLM flushes spend
// rows every PROXY_BATCH_WRITE_AT (10s) plus a random 0-5s, so a request
// arriving just after a flush waits up to ~15s. The samples happened to
// land mid-cycle. sourceVisibilityBudget is therefore set from the
// derivable worst case with margin, not from the samples.
//
// One thing the measurement ruled out that would otherwise be a real
// hazard: Langfuse's trace does NOT become visible before its
// observations. Had it, the fetcher could archive a trace whose token
// counts had not landed yet, and the content plane would report absent
// usage for a request that in fact had some. Observations completed
// within 40ms of the trace appearing, every time.
const (
	// sourceVisibilityBudget covers the slowest source-side delay, at
	// roughly 2x the derivable worst case (~15s).
	sourceVisibilityBudget = 30 * time.Second

	// MinJoinHealthLag is the floor the derived lag never goes below,
	// matching the figure documented in docs/CORRELATION.md §2.
	MinJoinHealthLag = 120 * time.Second

	// DefaultJoinHealthWindow is how wide a slice of time each report
	// covers. Wide enough to contain a meaningful number of events at
	// this deployment's request rate, narrow enough that a problem shows
	// up as a rate change rather than being diluted by hours of history.
	DefaultJoinHealthWindow = 15 * time.Minute
)

// JoinHealthLag returns how far behind "now" the measurement window must
// end, given the pipeline's own poll intervals.
//
// Deriving this rather than hardcoding 120s matters because the intervals
// are configurable: someone who sets --flush-interval to 5 minutes has a
// pipeline whose documents legitimately take 5 minutes longer to appear,
// and a fixed 120s lag would then report a healthy pipeline as broken
// every single cycle.
func JoinHealthLag(fetchInterval, indexInterval time.Duration) time.Duration {
	lag := sourceVisibilityBudget + fetchInterval + indexInterval
	if lag < MinJoinHealthLag {
		lag = MinJoinHealthLag
	}
	return lag
}

// JoinHealthConfig configures a JoinHealthReporter.
type JoinHealthConfig struct {
	ContentIndex string
	GatewayIndex string

	// Window is how wide the measured slice of time is; Lag is how far
	// behind now it ends. See JoinHealthLag.
	Window time.Duration
	Lag    time.Duration

	// BaselinePath points at join-baseline.json: the closed set of trace
	// IDs that can never be joined, because they predate the client
	// sending the join key. Empty disables the baseline, which is
	// honest but makes every report include a constant unexplained
	// remainder.
	BaselinePath string
}

// JoinHealthResult is one measurement of how well the two planes are
// joining. Every count is over the same window.
//
// The critical distinction is Unmatched vs ExpectedUnmatched. A single
// blended number would have to be interpreted against a fuzzy "normal
// range", and a metric with a fuzzy normal range cannot be alerted on --
// which is how a broken join stays invisible. Expected unmatched is a
// named, enumerated, closed set; anything else is an incident.
type JoinHealthResult struct {
	WindowStart time.Time
	WindowEnd   time.Time

	// Content plane, counted in distinct trace IDs.
	ContentTotal             int
	ContentMatched           int
	ContentExpectedUnmatched int
	ContentUnexplained       int

	// Gateway plane, also counted in distinct trace IDs -- NOT documents.
	// Three retried attempts of one request are three gateway documents
	// sharing one trace ID; counting documents would report an unmatched
	// rate of 3x reality on any retried request.
	GatewayTotal             int
	GatewayMatched           int
	GatewayExpectedUnmatched int
	GatewayUnexplained       int

	// GatewayDocsWithoutJoinKey counts gateway documents carrying no
	// trace.id at all. These are structurally uncorrelatable rather than
	// unmatched, and are reported separately so they never inflate a rate
	// whose denominator is "records that could have matched".
	GatewayDocsWithoutJoinKey int

	// GatewayDocs is the raw document count, kept alongside GatewayTotal
	// so the ratio between them is visible: it is the average attempts
	// per logical request, and a jump in it is a retry storm.
	GatewayDocs int
}

// ContentUnexplainedRate is the fraction of content events with no gateway
// partner and no recorded reason. Expected-unmatched events are removed
// from the numerator AND the denominator: they are not failures, and
// leaving them in would make the rate drift as their share of the window
// changes rather than as the join's health changes.
func (r JoinHealthResult) ContentUnexplainedRate() float64 {
	denom := r.ContentTotal - r.ContentExpectedUnmatched
	if denom <= 0 {
		return 0
	}
	return float64(r.ContentUnexplained) / float64(denom)
}

// GatewayUnexplainedRate is the same measurement in the other direction.
// Both are required: a one-directional check passes happily while one
// source is completely dead.
func (r JoinHealthResult) GatewayUnexplainedRate() float64 {
	denom := r.GatewayTotal - r.GatewayExpectedUnmatched
	if denom <= 0 {
		return 0
	}
	return float64(r.GatewayUnexplained) / float64(denom)
}

// Healthy reports whether both directions are fully explained. The
// threshold is exactly zero, not a tolerance: every legitimate reason for
// an unmatched event is either enumerated in the baseline or excluded by
// the lag, so anything left over is unexplained by construction.
func (r JoinHealthResult) Healthy() bool {
	return r.ContentUnexplained == 0 && r.GatewayUnexplained == 0
}

// JoinHealthReporter measures the join between the two planes.
type JoinHealthReporter struct {
	client   *esink.Client
	cfg      JoinHealthConfig
	baseline map[string]bool
}

// NewJoinHealthReporter loads the expected-unmatched baseline once. A
// missing baseline file is not an error -- it means "nothing is expected
// to be unmatched", which is the correct state for a deployment that has
// always sent the join key.
func NewJoinHealthReporter(client *esink.Client, cfg JoinHealthConfig) (*JoinHealthReporter, error) {
	if cfg.Window <= 0 {
		cfg.Window = DefaultJoinHealthWindow
	}
	if cfg.Lag <= 0 {
		cfg.Lag = MinJoinHealthLag
	}

	r := &JoinHealthReporter{client: client, cfg: cfg, baseline: map[string]bool{}}
	if cfg.BaselinePath == "" {
		return r, nil
	}

	data, err := os.ReadFile(cfg.BaselinePath)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("reading join baseline %q: %w", cfg.BaselinePath, err)
	}
	var doc struct {
		TraceIDs []string `json:"trace_ids"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing join baseline %q: %w", cfg.BaselinePath, err)
	}
	for _, id := range doc.TraceIDs {
		r.baseline[id] = true
	}
	return r, nil
}

// BaselineSize is how many trace IDs are enumerated as expected-unmatched.
func (r *JoinHealthReporter) BaselineSize() int { return len(r.baseline) }

// Measure runs one measurement over the lagged window.
func (r *JoinHealthReporter) Measure(ctx context.Context, now time.Time) (JoinHealthResult, error) {
	end := now.Add(-r.cfg.Lag)
	start := end.Add(-r.cfg.Window)
	res := JoinHealthResult{WindowStart: start, WindowEnd: end}

	contentIDs, _, err := r.traceIDsIn(ctx, r.cfg.ContentIndex, start, end)
	if err != nil {
		return res, fmt.Errorf("collecting content trace IDs: %w", err)
	}
	gatewayIDs, gwDocs, err := r.traceIDsIn(ctx, r.cfg.GatewayIndex, start, end)
	if err != nil {
		return res, fmt.Errorf("collecting gateway trace IDs: %w", err)
	}
	gwTotalDocs, err := r.docCountIn(ctx, r.cfg.GatewayIndex, start, end)
	if err != nil {
		return res, fmt.Errorf("counting gateway documents: %w", err)
	}

	res.GatewayDocs = gwTotalDocs
	res.GatewayDocsWithoutJoinKey = gwTotalDocs - gwDocs

	for id := range contentIDs {
		res.ContentTotal++
		switch {
		case gatewayIDs[id] > 0:
			res.ContentMatched++
		case r.baseline[id]:
			res.ContentExpectedUnmatched++
		default:
			res.ContentUnexplained++
		}
	}
	for id := range gatewayIDs {
		res.GatewayTotal++
		switch {
		case contentIDs[id] > 0:
			res.GatewayMatched++
		case r.baseline[id]:
			res.GatewayExpectedUnmatched++
		default:
			res.GatewayUnexplained++
		}
	}

	return res, nil
}

// traceIDsIn returns the distinct trace IDs in index over [start, end),
// and how many documents carried one.
//
// Uses a composite aggregation with after-key pagination rather than a
// terms aggregation with a large size: a terms agg silently truncates at
// its size limit, which would understate the denominator and make the
// unmatched rate look better than it is. A metric that fails safe by
// under-reporting problems is not failing safe.
func (r *JoinHealthReporter) traceIDsIn(ctx context.Context, index string, start, end time.Time) (map[string]int, int, error) {
	ids := map[string]int{}
	docs := 0
	var after map[string]any

	for page := 0; ; page++ {
		if page > joinHealthMaxPages {
			return nil, 0, fmt.Errorf("aggregation did not terminate after %d pages", joinHealthMaxPages)
		}
		composite := map[string]any{
			"size":    joinHealthPageSize,
			"sources": []any{map[string]any{"trace": map[string]any{"terms": map[string]any{"field": "trace.id"}}}},
		}
		if after != nil {
			composite["after"] = after
		}
		body := map[string]any{
			"size":  0,
			"query": rangeOnEventStart(start, end),
			"aggs":  map[string]any{"ids": map[string]any{"composite": composite}},
		}

		raw, err := r.client.Search(ctx, index, body)
		if err != nil {
			return nil, 0, err
		}
		var resp struct {
			Aggregations struct {
				IDs struct {
					AfterKey map[string]any `json:"after_key"`
					Buckets  []struct {
						Key      map[string]any `json:"key"`
						DocCount int            `json:"doc_count"`
					} `json:"buckets"`
				} `json:"ids"`
			} `json:"aggregations"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, 0, fmt.Errorf("parsing aggregation response: %w", err)
		}

		for _, b := range resp.Aggregations.IDs.Buckets {
			id, _ := b.Key["trace"].(string)
			if id == "" {
				continue
			}
			ids[id] += b.DocCount
			docs += b.DocCount
		}
		if len(resp.Aggregations.IDs.Buckets) == 0 || resp.Aggregations.IDs.AfterKey == nil {
			break
		}
		after = resp.Aggregations.IDs.AfterKey
	}
	return ids, docs, nil
}

func (r *JoinHealthReporter) docCountIn(ctx context.Context, index string, start, end time.Time) (int, error) {
	body := map[string]any{"size": 0, "query": rangeOnEventStart(start, end)}
	raw, err := r.client.Search(ctx, index, body)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return 0, fmt.Errorf("parsing count response: %w", err)
	}
	return resp.Hits.Total.Value, nil
}

// rangeOnEventStart builds the window filter.
//
// It filters on event.start, NOT @timestamp, and that is the whole reason
// this helper exists rather than the range being inlined. @timestamp means
// a different instant on each plane -- the gateway records request start,
// Langfuse records when its callback fired, which trails a successful
// request by its full duration. Windowing on @timestamp would put the two
// halves of the same request in different buckets whenever the request was
// slow, and report the resulting mismatch as a join failure. event.start
// is the same instant on both planes, agreeing to the millisecond. See
// docs/CORRELATION.md §5.
func rangeOnEventStart(start, end time.Time) map[string]any {
	return map[string]any{
		"range": map[string]any{
			"event.start": map[string]any{
				"gte":    start.UTC().Format(time.RFC3339Nano),
				"lt":     end.UTC().Format(time.RFC3339Nano),
				"format": "strict_date_optional_time_nanos",
			},
		},
	}
}

const (
	joinHealthPageSize = 1000
	joinHealthMaxPages = 1000
)
