package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"wiretap/internal/langfuse"
)

const (
	defaultEnrichConcurrency = 4
	defaultRateLimitPause    = 5 * time.Second
)

// enrichedResult is one candidate trace's outcome after an enrichment
// attempt.
type enrichedResult struct {
	core traceCore
	raw  json.RawMessage
	// skip means this trace should not be archived or marked seen this
	// poll -- it will come back around and be retried on a future poll
	// via the existing overlap-window mechanism (see PollOnce). See
	// enrichTrace's doc comment for which failures set this and why.
	skip bool
}

// enrichmentPool bounds how many GetTrace calls run concurrently during a
// single poll, and coordinates backoff across them.
//
// The langfuse.Client already retries a single request's own 429s with
// backoff (see internal/langfuse/client.go), but that protection is
// per-request: if N workers each independently hit the rate limit at
// roughly the same moment, each runs its own retry loop against the same
// server-side limit, which multiplies load right when the server is
// asking for less of it. pauseUntil is a second, coordinating layer: the
// first worker to see a rate-limit response (one that survived the
// client's own retries and still came back 429) sets a shared pause, and
// every worker -- not just the one that got limited -- waits it out
// before issuing its next request. This does not make the pool a true
// token-bucket limiter, but it stops concurrent workers from independently
// retrying into the same limit, which is the specific failure mode this
// exists to prevent.
type enrichmentPool struct {
	limit int

	mu         sync.Mutex
	pauseUntil time.Time
}

func newEnrichmentPool(limit int) *enrichmentPool {
	if limit < 1 {
		limit = defaultEnrichConcurrency
	}
	return &enrichmentPool{limit: limit}
}

// wait blocks until any shared pause has elapsed, or ctx is cancelled.
// Returns false if ctx was cancelled first.
func (p *enrichmentPool) wait(ctx context.Context) bool {
	p.mu.Lock()
	until := p.pauseUntil
	p.mu.Unlock()
	if until.IsZero() {
		return true
	}
	d := time.Until(until)
	if d <= 0 {
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// pauseFor extends the shared pause to at least d from now (never
// shortens an existing, longer pause set by another worker).
func (p *enrichmentPool) pauseFor(d time.Duration) {
	if d <= 0 {
		d = defaultRateLimitPause
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	until := time.Now().Add(d)
	if until.After(p.pauseUntil) {
		p.pauseUntil = until
	}
}

// enrichTrace fetches trace id's full detail and returns the raw bytes to
// archive in place of the list-shaped record.
//
// On failure it classifies the error using internal/langfuse's typed
// errors and decides skip vs. fatal:
//
//   - ErrNotFound: Langfuse's ingestion worker writes trace detail
//     asynchronously (the same reason the Fetcher's own overlap window
//     exists -- see this package's doc comment on overlapWindow). A trace
//     that just appeared in the list can 404 on detail for a few seconds
//     before the worker catches up. This is a real, expected race, not a
//     real absence, so it's skipped and retried next poll, not treated as
//     an error.
//   - ErrRateLimited, ErrTransport: also transient, also skipped and
//     retried next poll.
//   - anything else (ErrAuth, ErrDecode, an unrecognised status): systemic,
//     not per-trace. Retrying the same broken credential once per trace in
//     the page would not help and would just repeat the failure N times;
//     this is returned as a real error so the caller aborts the poll, the
//     same way a ListTraces failure already does.
//
// The alternative to skipping (archiving the list-shaped record as a
// fallback so nothing goes temporarily missing) was considered and
// rejected: a document with gen_ai.* fields silently absent because of a
// transient fetch race would be indistinguishable from the legitimate
// "Langfuse doesn't have this data" case (see internal/parse's package
// doc), quietly reintroducing the exact ambiguity this project's ECS
// mapper otherwise guarantees against (see
// TestMap_NoGenAIFieldEmittedAsZeroSubstituteForMissing). A temporarily
// missing document is honest about being incomplete; a permanently
// degraded one looks finished.
func (f *Fetcher) enrichTrace(ctx context.Context, id string) (raw json.RawMessage, skip bool, err error) {
	body, err := f.client.GetTraceRaw(ctx, id)
	if err == nil {
		return body, false, nil
	}

	var lfErr *langfuse.Error
	if errors.As(err, &lfErr) {
		switch lfErr.Kind {
		case langfuse.ErrNotFound, langfuse.ErrRateLimited, langfuse.ErrTransport:
			return nil, true, err
		}
	}
	return nil, false, err
}

// enrichPage fetches full detail for every candidate concurrently, bounded
// by cfg.EnrichConcurrency, and returns one result per candidate in the
// same order. A non-nil error means a systemic (fatal, non-skip) failure
// was seen and the whole poll should abort -- see enrichTrace.
func (f *Fetcher) enrichPage(ctx context.Context, candidates []traceCore) ([]enrichedResult, error) {
	if len(candidates) == 0 {
		return nil, nil
	}

	results := make([]enrichedResult, len(candidates))
	pool := newEnrichmentPool(f.cfg.EnrichConcurrency)
	sem := make(chan struct{}, pool.limit)
	var wg sync.WaitGroup

	for i, core := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, core traceCore) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = f.enrichOne(ctx, pool, core)
		}(i, core)
	}
	wg.Wait()

	for _, r := range results {
		if r.raw == nil && !r.skip {
			// enrichOne only leaves both raw and skip unset when
			// enrichTrace returned a fatal error; that error was already
			// logged in enrichOne, and re-running it here would just log
			// it twice, so this loop only needs to detect the condition
			// and produce one summarizing error for the caller.
			return results, fmt.Errorf("enriching trace %q: fatal error, see log", r.core.ID)
		}
	}
	return results, nil
}

func (f *Fetcher) enrichOne(ctx context.Context, pool *enrichmentPool, core traceCore) enrichedResult {
	f.enrichAttempted.Add(1)

	if !pool.wait(ctx) {
		f.enrichSkipped.Add(1)
		return enrichedResult{core: core, skip: true}
	}

	raw, skip, err := f.enrichTrace(ctx, core.ID)
	if err != nil {
		var lfErr *langfuse.Error
		if errors.As(err, &lfErr) && lfErr.Kind == langfuse.ErrRateLimited {
			pool.pauseFor(lfErr.RetryAfter)
		}
		if skip {
			f.enrichSkipped.Add(1)
			fmt.Fprintf(os.Stderr, "pipeline: enrichment for trace %q deferred to next poll: %v\n", core.ID, err)
			return enrichedResult{core: core, skip: true}
		}
		f.enrichFailed.Add(1)
		fmt.Fprintf(os.Stderr, "pipeline: enrichment for trace %q failed (fatal, aborting poll): %v\n", core.ID, err)
		return enrichedResult{core: core}
	}

	f.enrichSucceeded.Add(1)
	return enrichedResult{core: core, raw: raw}
}

// EnrichCounters is a point-in-time snapshot of a Fetcher's enrichment
// activity.
type EnrichCounters struct {
	Attempted int64
	Succeeded int64
	Skipped   int64
	Failed    int64
}

// EnrichCounters returns a snapshot of this Fetcher's enrichment activity
// so far.
func (f *Fetcher) EnrichCounters() EnrichCounters {
	return EnrichCounters{
		Attempted: f.enrichAttempted.Load(),
		Succeeded: f.enrichSucceeded.Load(),
		Skipped:   f.enrichSkipped.Load(),
		Failed:    f.enrichFailed.Load(),
	}
}
