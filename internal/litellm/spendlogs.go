package litellm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	// MaxPageSize is the largest page_size LiteLLM accepts. Asking for more
	// is a 422, not a silent clamp -- confirmed against a live proxy
	// (page_size=5000 returns "Input should be less than or equal to 100").
	MaxPageSize = 100

	// defaultPageSize matches MaxPageSize: every call this project makes
	// wants as many records per round trip as it can get.
	defaultPageSize = MaxPageSize

	// dateFormat is the ONLY timestamp format /spend/logs/v2 accepts for
	// start_date/end_date. It is not RFC3339: passing
	// "2026-07-30T23:05:00Z" returns a 400. Second granularity, space
	// separator, no zone -- values are interpreted as UTC.
	//
	// This is the single easiest thing to get wrong about this API, which
	// is why callers pass time.Time and never a preformatted string.
	dateFormat = "2006-01-02 15:04:05"

	// totalCountCap is the ceiling LiteLLM applies to the `total` it
	// reports (SPEND_LOGS_PAGINATION_COUNT_CAP in its source). Beyond this
	// many matching rows, `total` reads exactly 10000 and
	// `total_is_capped` is true. See SpendLogPage.HasMore for why this
	// makes total_pages unsafe to drive a fetch loop with.
	totalCountCap = 10000
)

// ListParams selects one page of spend records.
//
// StartDate and EndDate are both required by the API; ListSpendLogs
// returns an ErrBadRequest-shaped failure from the server if either is
// zero rather than guessing a window, because a wrong default here means
// silently fetching either nothing or the entire history.
type ListParams struct {
	StartDate time.Time
	EndDate   time.Time

	// Page is 1-based. Zero means 1.
	Page int
	// PageSize defaults to MaxPageSize and is capped at it -- asking for
	// more is a 422 from the server, so it is clamped here instead.
	PageSize int

	// SortBy / SortOrder default to ascending startTime, which is the only
	// ordering that makes checkpointed incremental fetching coherent: a
	// fetcher that walks pages while new rows arrive needs the oldest rows
	// to hold still, and only ascending order guarantees that.
	SortBy    string
	SortOrder string

	// StatusFilter narrows to "success" or "failure" server-side. Empty
	// means both. Rarely wanted by the pipeline (which archives
	// everything) but useful for diagnostics and for cmd tooling.
	StatusFilter string
}

func (p ListParams) query() (url.Values, error) {
	if p.StartDate.IsZero() || p.EndDate.IsZero() {
		return nil, &Error{
			Kind: ErrBadRequest,
			Err:  fmt.Errorf("StartDate and EndDate are both required (the API rejects a missing one with a 400)"),
		}
	}

	page := p.Page
	if page < 1 {
		page = 1
	}
	size := p.PageSize
	if size <= 0 {
		size = defaultPageSize
	}
	if size > MaxPageSize {
		size = MaxPageSize
	}
	sortBy := p.SortBy
	if sortBy == "" {
		sortBy = "startTime"
	}
	sortOrder := p.SortOrder
	if sortOrder == "" {
		sortOrder = "asc"
	}

	q := url.Values{}
	q.Set("start_date", p.StartDate.UTC().Format(dateFormat))
	q.Set("end_date", p.EndDate.UTC().Format(dateFormat))
	q.Set("page", strconv.Itoa(page))
	q.Set("page_size", strconv.Itoa(size))
	q.Set("sort_by", sortBy)
	q.Set("sort_order", sortOrder)
	if p.StatusFilter != "" {
		q.Set("status_filter", p.StatusFilter)
	}
	return q, nil
}

// SpendLogPage is one page of GET /spend/logs/v2. Data holds each record as
// still-undecoded JSON, for the same reason internal/langfuse.TracePage
// does: the fetch stage archives records byte-for-byte and must never
// round-trip them through a Go struct, which would silently drop every
// field this package doesn't happen to model. Callers wanting typed access
// decode elements themselves (see SpendLog, and internal/parse).
type SpendLogPage struct {
	Data     []json.RawMessage
	Total    int
	Page     int
	PageSize int
	// TotalPages is what the server reported. Do not drive a fetch loop
	// with it -- see HasMore.
	TotalPages int
	// TotalIsCapped is the server telling you Total is a ceiling, not a
	// count: there are more than 10,000 matching rows and it stopped
	// counting.
	TotalIsCapped bool
}

// HasMore reports whether another page is worth requesting.
//
// It deliberately ignores TotalPages, because TotalPages is derived from
// Total, and Total is capped at 10,000 by the server. On a table with more
// rows than that, TotalPages understates reality and a loop driven by it
// stops early -- silently, having fetched a prefix of the data and
// believing it finished. Fetching until a page comes back short is the
// only condition that stays correct when the count is a lie.
func (p *SpendLogPage) HasMore() bool {
	return len(p.Data) >= p.PageSize && p.PageSize > 0
}

// ListSpendLogs fetches one page of spend records.
//
// Callers walk pages by incrementing ListParams.Page while HasMore reports
// true, rather than up to TotalPages -- see HasMore.
func (c *Client) ListSpendLogs(ctx context.Context, params ListParams) (*SpendLogPage, error) {
	body, err := c.ListSpendLogsRaw(ctx, params)
	if err != nil {
		return nil, err
	}

	var raw struct {
		Data          []json.RawMessage `json:"data"`
		Total         int               `json:"total"`
		Page          int               `json:"page"`
		PageSize      int               `json:"page_size"`
		TotalPages    int               `json:"total_pages"`
		TotalIsCapped bool              `json:"total_is_capped"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, &Error{Kind: ErrDecode, Err: fmt.Errorf("parsing spend logs response: %w", err)}
	}
	// A response missing the envelope entirely (e.g. someone pointed this
	// at /spend/logs, which returns a bare array or daily aggregates)
	// decodes without error into a zero-valued struct. Catch it here
	// rather than let a fetch loop conclude there is no data.
	if raw.Data == nil && raw.PageSize == 0 && raw.Total == 0 {
		return nil, &Error{
			Kind: ErrDecode,
			Err:  fmt.Errorf("response carries no pagination envelope -- is this /spend/logs/v2? (/spend/logs returns a different shape)"),
		}
	}
	return &SpendLogPage{
		Data:          raw.Data,
		Total:         raw.Total,
		Page:          raw.Page,
		PageSize:      raw.PageSize,
		TotalPages:    raw.TotalPages,
		TotalIsCapped: raw.TotalIsCapped,
	}, nil
}

// ListSpendLogsRaw fetches one page and returns the response body exactly
// as LiteLLM sent it, undecoded -- the counterpart to
// internal/langfuse.GetTraceRaw, and for the same reason: an archive is
// only replayable through a corrected mapper if it holds what the API
// actually said, not this package's current understanding of it.
func (c *Client) ListSpendLogsRaw(ctx context.Context, params ListParams) (json.RawMessage, error) {
	q, err := params.query()
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, http.MethodGet, "/spend/logs/v2", q)
	if err != nil {
		return nil, err
	}
	body, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

// ErrorInformation is LiteLLM's structured account of why a request
// failed. Present only on records with Status "failure"; nil otherwise.
// This is the gateway plane's headline contribution -- the content plane
// has the same facts only as English prose (see docs/CORRELATION.md).
type ErrorInformation struct {
	// ErrorCode is the HTTP status as a string, e.g. "429", "401".
	ErrorCode string `json:"error_code"`
	// ErrorClass is the Python exception class, e.g. "BudgetExceededError",
	// "KeyNotFoundError". The field detections group on.
	ErrorClass   string `json:"error_class"`
	ErrorMessage string `json:"error_message"`
	LLMProvider  string `json:"llm_provider"`
	// Traceback is deliberately modeled but never mapped downstream: it is
	// LiteLLM's internal file paths, which carry no analytic value and real
	// storage cost. Kept here so its presence is visible to anyone reading
	// this struct rather than surprising them in raw JSON.
	Traceback string `json:"traceback"`
}

// SpendLogMetadata is the subset of a record's metadata this project
// reads. The real object carries ~30 keys of LiteLLM-internal plumbing
// plus model_map_information, a ~90-key static pricing table repeated
// verbatim on every single record.
type SpendLogMetadata struct {
	// SpendLogsMetadata is caller-supplied metadata preserved verbatim by
	// LiteLLM -- the ONLY channel by which a caller's own identifier
	// reaches a spend record, and therefore where this project's join key
	// lives. See TraceID.
	SpendLogsMetadata map[string]any `json:"spend_logs_metadata"`

	// UserAPIKeyAlias is the virtual key's human-readable name. Present on
	// success and on enforcement failures; absent when the attempted key
	// was never valid (there is no alias for a key that does not exist).
	UserAPIKeyAlias string `json:"user_api_key_alias"`
	// UserAPIKey is the SHA-256 hash of the virtual key. Never the key
	// itself. On an auth failure this is the hash of the key that was
	// *attempted*, which is what makes credential-spray clustering
	// possible.
	UserAPIKey       string `json:"user_api_key"`
	UserAPIKeyUserID string `json:"user_api_key_user_id"`
	UserAPIKeyTeamID string `json:"user_api_key_team_id"`

	// LiteLLMCallID is LiteLLM's own per-attempt identifier, also returned
	// to the caller as the x-litellm-call-id response header on success
	// (but not on a refusal).
	LiteLLMCallID string `json:"litellm_call_id"`

	ErrorInformation *ErrorInformation `json:"error_information"`

	// UsageObject and CostBreakdown are nil on a refused request, and that
	// is the discriminator this project relies on. The top-level
	// prompt_tokens/completion_tokens/spend fields are NOT NULL columns
	// defaulting to 0, so they read as a measured zero on a request that
	// never ran. These two being nil is LiteLLM stating it has no usage or
	// cost data -- absent, not zero.
	UsageObject   map[string]any `json:"usage_object"`
	CostBreakdown map[string]any `json:"cost_breakdown"`

	// AttemptedRetries is LiteLLM's own upstream retry count -- 0 on
	// success, null on failure. Pointer so those two stay distinguishable.
	// Note this is the *server-side* count, not the client's
	// X-Stainless-Retry-Count, which reaches neither plane.
	AttemptedRetries *int `json:"attempted_retries"`

	LiteLLMOverheadTimeMs *float64 `json:"litellm_overhead_time_ms"`
	RequesterIPAddress    string   `json:"requester_ip_address"`
}

// SpendLog is one per-request gateway record, typed. Only the fields
// something downstream reads are modeled; see internal/parse for the
// archive-replay decoder, which is deliberately separate for the same
// reason internal/parse doesn't import internal/langfuse.
//
// Numeric fields that LiteLLM reports as a NOT NULL zero on a request that
// never ran are plain values here, not pointers, on purpose: this struct
// reports what the API said. Deciding that a zero means "absent" requires
// the UsageObject/CostBreakdown discriminator and belongs to the parser,
// not to a transport type that would then be lying about its source.
type SpendLog struct {
	RequestID string `json:"request_id"`
	CallType  string `json:"call_type"`
	// APIKey is the SHA-256 hash of the virtual key. Never the key itself.
	APIKey string `json:"api_key"`

	Spend            float64 `json:"spend"`
	TotalTokens      int     `json:"total_tokens"`
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`

	StartTime           string `json:"startTime"`
	EndTime             string `json:"endTime"`
	CompletionStartTime string `json:"completionStartTime"`
	RequestDurationMs   int    `json:"request_duration_ms"`

	// Model means different things by status, exactly as it does on a
	// Langfuse observation: on success it is the model that *served* the
	// request, provider-prefixed ("groq/llama-3.3-70b-versatile"); on a
	// failure nothing served it, so it is the model *requested*, unprefixed.
	Model string `json:"model"`
	// ModelGroup, CustomLLMProvider, ModelID and APIBase are all "" on a
	// failure -- LiteLLM never got far enough to route.
	ModelGroup        string `json:"model_group"`
	CustomLLMProvider string `json:"custom_llm_provider"`
	ModelID           string `json:"model_id"`
	APIBase           string `json:"api_base"`

	User    string `json:"user"`
	EndUser string `json:"end_user"`
	TeamID  string `json:"team_id"`
	// SessionID is unusable as a join key: on a failure LiteLLM discards
	// the caller's session_id and substitutes a fresh random UUID. See
	// docs/CORRELATION.md.
	SessionID string `json:"session_id"`

	RequesterIPAddress string   `json:"requester_ip_address"`
	RequestTags        []string `json:"request_tags"`
	CacheHit           string   `json:"cache_hit"`

	// Status is "success" or "failure" -- already ECS event.outcome's
	// vocabulary, which is not a coincidence worth relying on but is
	// convenient.
	Status string `json:"status"`

	Metadata SpendLogMetadata `json:"metadata"`
}

// TraceID returns the caller-supplied join key carried through
// metadata.spend_logs_metadata.trace_id, and whether it was present.
//
// This is a typed accessor rather than a struct field because
// spend_logs_metadata is an arbitrary caller-controlled map, not a
// LiteLLM-defined shape: modeling it as a struct would imply a contract
// that does not exist. It is also the single most important field in this
// package -- absent, no cross-plane correlation is possible for refused
// requests at all -- so it gets a named method whose failure is a bool a
// caller must handle, not an empty string that reads as a valid ID.
func (s SpendLog) TraceID() (string, bool) {
	if s.Metadata.SpendLogsMetadata == nil {
		return "", false
	}
	v, ok := s.Metadata.SpendLogsMetadata["trace_id"]
	if !ok {
		return "", false
	}
	id, ok := v.(string)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

// Failed reports whether this record describes a request the proxy
// refused. Uses Status rather than the presence of ErrorInformation
// because Status is the field LiteLLM indexes and filters on.
func (s SpendLog) Failed() bool { return s.Status == "failure" }

// HasUsage reports whether LiteLLM actually measured token usage for this
// request, as opposed to reporting the NOT NULL zero its schema requires.
// See SpendLogMetadata.UsageObject.
func (s SpendLog) HasUsage() bool { return s.Metadata.UsageObject != nil }

// HasCost reports whether LiteLLM actually computed a cost, as opposed to
// reporting a default zero. See SpendLogMetadata.CostBreakdown.
func (s SpendLog) HasCost() bool { return s.Metadata.CostBreakdown != nil }

// DecodeSpendLogs decodes a page's raw records into typed SpendLogs.
// Separate from ListSpendLogs so the fetch stage can archive Data
// untouched and only the callers that want typed access pay for decoding.
func DecodeSpendLogs(raw []json.RawMessage) ([]SpendLog, error) {
	out := make([]SpendLog, 0, len(raw))
	for i, r := range raw {
		var s SpendLog
		if err := json.Unmarshal(r, &s); err != nil {
			return nil, &Error{Kind: ErrDecode, Err: fmt.Errorf("decoding spend log record %d: %w", i, err)}
		}
		out = append(out, s)
	}
	return out, nil
}
