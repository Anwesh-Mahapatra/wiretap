package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"wiretap/internal/litellm"
)

const (
	// gatewayOverlapWindow re-queries a window behind the last-seen record
	// on every poll, for the same reason the Langfuse fetcher does: a
	// record can become visible to the API *after* a record with a later
	// timestamp, so a cutoff set to "the newest thing I saw" would step
	// over anything still in flight.
	//
	// The gateway needs this more than the content plane does, not less.
	// LiteLLM writes spend rows in batches every PROXY_BATCH_WRITE_AT
	// (10s) plus a random 0-5s, so rows genuinely appear out of order
	// relative to their own startTime. Measured visibility lag is ~7s;
	// the theoretical worst case is ~15s. Five minutes is two orders of
	// magnitude above that, which is the right kind of margin for a
	// window whose only cost is re-reading rows the seen-set then
	// discards.
	gatewayOverlapWindow = 5 * time.Minute

	// gatewayPageSize is capped by the API at 100 (see litellm.MaxPageSize).
	gatewayPageSize = litellm.MaxPageSize

	// gatewayMaxPagesPerPoll bounds one poll's work so a first run against
	// a long history cannot block the loop indefinitely. Anything left is
	// picked up on the next poll, because the checkpoint only advances
	// past records actually written.
	gatewayMaxPagesPerPoll = 50
)

// GatewayFetchConfig configures a GatewayFetcher.
//
// OutPath and StatePath must NOT be the same files the Langfuse Fetcher
// uses. Each archive has exactly one writer and each checkpoint exactly
// one owner -- that invariant is what keeps two fetchers from reproducing
// the duplicate-writer race described in arch.md, and it is the reason
// these are explicit parameters with no defaults that could accidentally
// coincide.
type GatewayFetchConfig struct {
	OutPath   string
	StatePath string

	// SkipHealthchecks drops LiteLLM's own health-check spend rows before
	// they ever reach the archive -- the gateway-plane counterpart to
	// FetchConfig.SkipHealthchecks, honouring the same --skip-healthchecks
	// flag so the two planes cannot end up with different ideas of what
	// counts as real traffic. See gatewayRecordCore.isHealthCheck.
	SkipHealthchecks bool

	// From seeds the checkpoint's cutoff, but only when the checkpoint is
	// otherwise empty. A checkpoint that already has a cutoff always wins,
	// so restarting with a stale --from can never rewind ingestion.
	From time.Time

	// LookbackOnFirstRun bounds how much history a first run pulls when
	// From is zero. LiteLLM never expires spend rows by default
	// (maximum_spend_logs_retention_period is unset), so "everything"
	// is an unbounded fetch against a table that only grows. Zero means
	// use defaultGatewayLookback.
	LookbackOnFirstRun time.Duration
}

// defaultGatewayLookback is how far back a first run reaches when nothing
// else says otherwise. Deliberately modest: the archive is the durable
// record, and someone who genuinely wants all history can pass an explicit
// From, which is a decision worth making on purpose rather than getting by
// default from an empty state file.
const defaultGatewayLookback = 24 * time.Hour

type gatewaySeenEntry struct {
	RequestID string    `json:"request_id"`
	StartTime time.Time `json:"start_time"`
}

type gatewayCheckpointState struct {
	// Cutoff is the start of the next poll's window.
	Cutoff time.Time `json:"cutoff"`
	// Seen holds request IDs already written, within the overlap window,
	// so re-querying that window does not re-archive them. Keyed on
	// request_id -- the primary key of LiteLLM_SpendLogs -- and NOT on
	// trace ID, because three retried attempts share one trace ID and are
	// three distinct records that must all be archived.
	Seen []gatewaySeenEntry `json:"seen"`
}

// GatewayFetcher polls LiteLLM's spend API and appends each new record to
// an NDJSON archive, one record per line, byte-for-byte as the API
// returned it. It is the gateway-plane counterpart to Fetcher and is
// deliberately shaped the same way.
type GatewayFetcher struct {
	client *litellm.Client
	cfg    GatewayFetchConfig
	out    *ndjsonWriter
	cp     *gatewayCheckpointState
}

// NewGatewayFetcher opens (creating if necessary) the archive and
// checkpoint files named in cfg.
func NewGatewayFetcher(client *litellm.Client, cfg GatewayFetchConfig) (*GatewayFetcher, error) {
	cp, err := loadGatewayCheckpoint(cfg.StatePath)
	if err != nil {
		return nil, err
	}
	if cp.Cutoff.IsZero() {
		switch {
		case !cfg.From.IsZero():
			cp.Cutoff = cfg.From
		default:
			lookback := cfg.LookbackOnFirstRun
			if lookback <= 0 {
				lookback = defaultGatewayLookback
			}
			cp.Cutoff = time.Now().UTC().Add(-lookback)
		}
	}

	out, err := newNDJSONWriter(cfg.OutPath)
	if err != nil {
		return nil, err
	}
	return &GatewayFetcher{client: client, cfg: cfg, out: out, cp: cp}, nil
}

// Close closes the archive file. It does not save the checkpoint -- see
// SaveCheckpoint, kept separate for the same reason the Langfuse fetcher
// separates them.
func (f *GatewayFetcher) Close() error { return f.out.Close() }

// SaveCheckpoint persists the fetcher's current checkpoint to disk.
func (f *GatewayFetcher) SaveCheckpoint() error {
	return atomicWriteJSON(f.cfg.StatePath, f.cp)
}

// PollOnce walks every page of spend records from the checkpoint's cutoff
// onward, appending each unseen one to the archive and advancing the
// checkpoint in memory.
//
// Pagination stops on a short page rather than at the server's reported
// total_pages: LiteLLM caps the total it reports at 10,000, so on a large
// table total_pages understates reality and a loop driven by it would stop
// early having silently fetched a prefix. See litellm.SpendLogPage.HasMore.
func (f *GatewayFetcher) PollOnce(ctx context.Context) (emitted, skipped int, err error) {
	seen := make(map[string]time.Time, len(f.cp.Seen))
	for _, e := range f.cp.Seen {
		seen[e.RequestID] = e.StartTime
	}

	cutoff := f.cp.Cutoff
	// end is "now plus a little": the API's window is inclusive and rows
	// land with a lag, so an end of exactly now would exclude nothing but
	// costs nothing to pad.
	end := time.Now().UTC().Add(time.Minute)
	maxTime := cutoff

	for page := 1; page <= gatewayMaxPagesPerPoll; page++ {
		resp, perr := f.client.ListSpendLogs(ctx, litellm.ListParams{
			StartDate: cutoff,
			EndDate:   end,
			Page:      page,
			PageSize:  gatewayPageSize,
			SortBy:    "startTime",
			SortOrder: "asc",
		})
		if perr != nil {
			// Return what was already written rather than discarding it:
			// the archive lines are durable, and the checkpoint simply
			// does not advance past them, so the next poll retries.
			return emitted, skipped, fmt.Errorf("listing spend logs (page %d): %w", page, perr)
		}

		for _, raw := range resp.Data {
			var core gatewayRecordCore
			if uerr := json.Unmarshal(raw, &core); uerr != nil {
				// A record we cannot even read the ID of cannot be
				// checkpointed, so archiving it would mean re-archiving it
				// forever. Skip and count it.
				skipped++
				continue
			}
			if core.RequestID == "" {
				skipped++
				continue
			}
			if _, already := seen[core.RequestID]; already {
				skipped++
				continue
			}

			if f.cfg.SkipHealthchecks && core.isHealthCheck() {
				// Marked seen and allowed to advance the cutoff, exactly as
				// the content plane's fetcher treats a health-check trace:
				// this is a permanent decision about the record, so there is
				// nothing to gain from re-reading it on every poll inside
				// the overlap window, and a quiet period carrying only
				// health checks must still move the checkpoint forward.
				skipped++
				startTime := parseGatewayRecordTime(core.StartTime)
				seen[core.RequestID] = startTime
				if startTime.After(maxTime) {
					maxTime = startTime
				}
				continue
			}

			if werr := f.out.WriteLine(raw); werr != nil {
				return emitted, skipped, fmt.Errorf("archiving spend record %q: %w", core.RequestID, werr)
			}
			startTime := parseGatewayRecordTime(core.StartTime)
			seen[core.RequestID] = startTime
			emitted++
			if startTime.After(maxTime) {
				maxTime = startTime
			}
		}

		if !resp.HasMore() {
			break
		}
	}

	// Advance the cutoff to the newest record seen, minus the overlap
	// window, so anything still in flight is re-queried next time.
	nextCutoff := maxTime.Add(-gatewayOverlapWindow)
	if nextCutoff.After(f.cp.Cutoff) {
		f.cp.Cutoff = nextCutoff
	}

	// Prune the seen-set to the overlap window. Entries older than the
	// cutoff can never be re-returned by a future query anyway, so keeping
	// them would only grow the checkpoint file without bound.
	pruned := make([]gatewaySeenEntry, 0, len(seen))
	for id, ts := range seen {
		if ts.IsZero() || !ts.Before(f.cp.Cutoff) {
			pruned = append(pruned, gatewaySeenEntry{RequestID: id, StartTime: ts})
		}
	}
	f.cp.Seen = pruned

	return emitted, skipped, nil
}

// gatewayRecordCore is the minimum this stage needs to decide whether a
// record is new, where it sits in time, and whether the opt-in
// health-check filter applies. Everything else stays undecoded: the fetch
// stage archives bytes, it does not interpret them. Interpretation is
// internal/parse's job, at replay time, so a mapper fix months from now
// sees what the API actually said.
//
// This mirrors traceCore on the content plane, including the fact that it
// duplicates a decision internal/parse also makes: the fetch stage cannot
// import that package's answer without importing its whole view of a
// record, which is exactly the coupling the two-stage split exists to
// avoid. Keep isHealthCheck below and parse.isGatewayHealthCheck in step.
type gatewayRecordCore struct {
	RequestID string `json:"request_id"`
	StartTime string `json:"startTime"`

	RequestTags []string `json:"request_tags"`
	APIKey      string   `json:"api_key"`
	TeamID      string   `json:"team_id"`
	Metadata    struct {
		UserAPIKey       string `json:"user_api_key"`
		UserAPIKeyAlias  string `json:"user_api_key_alias"`
		UserAPIKeyTeamID string `json:"user_api_key_team_id"`
	} `json:"metadata"`
}

// isHealthCheck reports whether this record is one of LiteLLM's own model
// health checks. See parse.isGatewayHealthCheck for the full account of
// where each of these fields comes from and why the tag alone is not
// enough; the short version is that LiteLLM stamps healthCheckTag onto a
// health check both as a request tag and as the identity of the synthetic
// service account it bills, and either stamp is sufficient evidence.
func (c gatewayRecordCore) isHealthCheck() bool {
	if hasTag(c.RequestTags, healthCheckTag) {
		return true
	}
	for _, identity := range []string{
		c.APIKey,
		c.TeamID,
		c.Metadata.UserAPIKey,
		c.Metadata.UserAPIKeyAlias,
		c.Metadata.UserAPIKeyTeamID,
	} {
		if identity == healthCheckTag {
			return true
		}
	}
	return false
}

func parseGatewayRecordTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

func loadGatewayCheckpoint(path string) (*gatewayCheckpointState, error) {
	var cp gatewayCheckpointState
	if err := loadJSONIfExists(path, &cp); err != nil {
		return nil, err
	}
	return &cp, nil
}
