package langfuse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
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

// GetTrace fetches one trace by ID, with observations expanded to full
// objects rather than the ID strings ListTraces returns.
func (c *Client) GetTrace(ctx context.Context, id string) (*Trace, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/public/traces/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}

	body, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}

	var t Trace
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, &Error{Kind: ErrDecode, Err: fmt.Errorf("parsing trace response: %w", err)}
	}
	return &t, nil
}
