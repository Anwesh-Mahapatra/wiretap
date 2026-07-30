package langfuse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultPageLimit = 100

// ListTracesParams filters and paginates a call to ListTraces. Limit and
// Page default to 100 and 1 respectively when left zero. A zero
// FromTimestamp omits the filter (no lower bound).
type ListTracesParams struct {
	Page          int
	Limit         int
	OrderBy       string
	FromTimestamp time.Time
}

// TracePage is one page of Langfuse's GET /api/public/traces response. Data
// holds each trace as still-undecoded JSON: callers that only need to
// archive traces byte-for-byte (tracepump) never have to round-trip them
// through a Go struct, and callers that do want typed access can decode
// each element themselves (see internal/parse).
type TracePage struct {
	Data       []json.RawMessage
	Page       int
	TotalPages int
}

// ListTraces fetches one page of traces, newest-filterable via
// params.FromTimestamp. Pagination is Langfuse's own page/totalPages
// scheme, surfaced on TracePage as-is -- callers walk pages by incrementing
// ListTracesParams.Page until Page >= TotalPages.
func (c *Client) ListTraces(ctx context.Context, params ListTracesParams) (*TracePage, error) {
	page := params.Page
	if page < 1 {
		page = 1
	}
	limit := params.Limit
	if limit <= 0 {
		limit = defaultPageLimit
	}

	q := url.Values{}
	q.Set("page", strconv.Itoa(page))
	q.Set("limit", strconv.Itoa(limit))
	if params.OrderBy != "" {
		q.Set("orderBy", params.OrderBy)
	}
	if !params.FromTimestamp.IsZero() {
		q.Set("fromTimestamp", params.FromTimestamp.Format(time.RFC3339Nano))
	}

	req, err := c.newRequest(ctx, http.MethodGet, "/api/public/traces", q)
	if err != nil {
		return nil, err
	}

	body, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}

	var raw struct {
		Data []json.RawMessage `json:"data"`
		Meta struct {
			Page       int `json:"page"`
			TotalPages int `json:"totalPages"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, &Error{Kind: ErrDecode, Err: fmt.Errorf("parsing traces response: %w", err)}
	}
	return &TracePage{Data: raw.Data, Page: raw.Meta.Page, TotalPages: raw.Meta.TotalPages}, nil
}

// Usage is a Langfuse observation's token accounting.
type Usage struct {
	Input  int    `json:"input"`
	Output int    `json:"output"`
	Total  int    `json:"total"`
	Unit   string `json:"unit"`
}

// Observation is one full generation/span/event within a trace, as returned
// by the trace-detail endpoint. The list endpoint (ListTraces) does not
// carry these -- only ID strings, inline on each trace's own "observations"
// field -- which is why token counts and the answering model are only ever
// available after a GetTrace call.
//
// The real response carries roughly 40 fields (confirmed by capturing a
// live GET /api/public/traces/{id} response -- see
// internal/langfuse/testdata/detail_truncated.json); this struct models
// exactly the ones something downstream reads. Everything else is silently
// dropped by encoding/json, which is correct for fields nothing needs --
// but Metadata and ModelParameters below were *wrongly* being dropped
// until this change, because gen_ai.request.model and
// gen_ai.request.max_tokens live inside them and nowhere else.
type Observation struct {
	ID        string  `json:"id"`
	Type      string  `json:"type"`
	Name      string  `json:"name"`
	Model     string  `json:"model"`
	Input     any     `json:"input"`
	Output    any     `json:"output"`
	Usage     *Usage  `json:"usage"`
	Latency   float64 `json:"latency"`
	StartTime string  `json:"startTime"`
	EndTime   string  `json:"endTime"`

	Metadata        ObservationMetadata        `json:"metadata"`
	ModelParameters ObservationModelParameters `json:"modelParameters"`
}

// ObservationMetadata is the subset of an observation's metadata this
// project reads. The real object is a large LiteLLM-internal blob --
// auth/budget/routing plumbing, dozens of fields -- with no Langfuse
// meaning of its own; only ModelGroup is modeled here.
type ObservationMetadata struct {
	// ModelGroup is the model the *caller* requested (e.g.
	// "llama-3.3-70b-versatile"), as distinct from Observation.Model, the
	// model that actually answered (e.g. "groq/llama-3.3-70b-versatile"
	// -- LiteLLM's provider-prefixed deployment name). Confirmed present
	// and consistently different from Observation.Model across every
	// trace this project has captured. This is a LiteLLM convention
	// surfaced through Langfuse's generic metadata field, not a
	// documented Langfuse concept -- there is no contract guaranteeing it
	// stays here across LiteLLM versions.
	ModelGroup string `json:"model_group"`
}

// ObservationModelParameters is the subset of an observation's
// modelParameters this project reads. Real data also carries stream,
// max_retries, extra_body, and system_fingerprint; none of those are
// modeled because nothing downstream reads them. MaxTokens is a pointer
// because it is only present when the caller actually set max_tokens on
// the request (confirmed: present and 5 on a trace whose scenario set
// maxTokens: 5; the key is simply absent, not present-and-zero, on traces
// whose scenario didn't) -- a plain int would make "not set" and "set to
// 0" indistinguishable.
type ObservationModelParameters struct {
	MaxTokens *int `json:"max_tokens"`
}

// CompletionID extracts the provider's completion ID (e.g.
// "chatcmpl-da63253c-b51b-4557-9cc4-c3ed0aa1b9dd") from the observation's
// own ID. This project's Langfuse integration constructs observation IDs
// as "time-<HHMMSS-ffffff>_<completionID>" -- confirmed against every
// trace this project has captured. There is no dedicated Langfuse field
// for the completion ID, so this is a typed accessor rather than a struct
// tag: a plain `json:"id"` field would hide that Observation.ID is doing
// double duty, and a future LiteLLM/Langfuse version could change this
// naming convention without changing the field name, which a struct tag
// would not surface but a failing accessor test would.
func (o Observation) CompletionID() (id string, ok bool) {
	_, after, found := strings.Cut(o.ID, "_")
	if !found || after == "" {
		return "", false
	}
	return after, true
}

// Trace is a single Langfuse trace as returned by the trace-detail
// endpoint, with observations expanded to full objects (see Observation).
type Trace struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	UserID       string        `json:"userId"`
	SessionID    string        `json:"sessionId"`
	Tags         []string      `json:"tags"`
	Input        any           `json:"input"`
	Output       any           `json:"output"`
	Latency      float64       `json:"latency"`
	Observations []Observation `json:"observations"`
}

// GetTraceRaw fetches one trace by ID and returns the response body exactly
// as Langfuse sent it, undecoded. Exists for callers that need to archive
// the detail response byte-for-byte (see internal/pipeline's fetch
// enrichment) rather than round-trip it through Trace, which would only
// preserve the subset of fields this package's structs declare -- silently
// dropping the rest, which is fine for typed access but not for an archive
// meant to be a faithful record of what the API actually returned.
func (c *Client) GetTraceRaw(ctx context.Context, id string) (json.RawMessage, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/public/traces/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	body, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

// GetTrace fetches one trace by ID, with observations expanded to full
// objects rather than the ID strings ListTraces returns.
func (c *Client) GetTrace(ctx context.Context, id string) (*Trace, error) {
	body, err := c.GetTraceRaw(ctx, id)
	if err != nil {
		return nil, err
	}

	var t Trace
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, &Error{Kind: ErrDecode, Err: fmt.Errorf("parsing trace response: %w", err)}
	}
	return &t, nil
}
