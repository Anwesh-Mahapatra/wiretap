package parse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"wiretap/internal/model"
)

// ParseGatewayLine converts one NDJSON line from the gateway archive -- one
// LiteLLM spend record, exactly as GET /spend/logs/v2 returned it -- into a
// model.LLMEvent carrying a GatewayDetail.
//
// It is the gateway-plane counterpart to ParseLine and follows the same
// discipline: null-safe throughout, a *LineError carrying the line number
// and a truncated excerpt on anything undecodable, and no assumption that
// a field present in one sample is present in all. That last rule matters
// more here than it does for Langfuse, because a LiteLLM spend record is
// genuinely two different shapes depending on whether the request ran.
//
// # The two shapes, and the zeros that are not measurements
//
// A successful record carries a completion ID as request_id, a
// provider-prefixed served model, a provider, token counts, and a cost. A
// refused record -- budget block, auth failure, rate limit -- carries a
// bare UUID as request_id, the *requested* model unprefixed, empty
// provider/model_group/api_base, and:
//
//	"spend": 0.0, "total_tokens": 0, "prompt_tokens": 0, "completion_tokens": 0
//
// Those zeros are not measurements. LiteLLM_SpendLogs declares those
// columns NOT NULL DEFAULT 0, so a request that never reached a model
// still reports them as zero, and a parser that believes them indexes a
// blocked request as a free successful one. This project has already been
// bitten by exactly that on the content plane (see notes.md).
//
// The discriminator is not the zeros themselves but LiteLLM's own
// statement about whether it has data: metadata.usage_object and
// metadata.cost_breakdown are null precisely when there is nothing to
// report. This parser reads those, not the zeros, and leaves token counts
// and cost genuinely absent when they are null -- so "we do not know" and
// "it was free" stay distinguishable.
func ParseGatewayLine(line []byte, lineNo int) (*model.LLMEvent, error) {
	var wr wireSpendLog
	if err := json.Unmarshal(line, &wr); err != nil {
		return nil, newLineError(lineNo, line, fmt.Errorf("decoding spend record: %w", err))
	}
	if wr.RequestID == "" {
		return nil, newLineError(lineNo, line, fmt.Errorf("spend record has no request_id"))
	}

	gw := &model.GatewayDetail{
		RequestID:   wr.RequestID,
		CallID:      wr.Metadata.LiteLLMCallID,
		KeyAlias:    wr.Metadata.UserAPIKeyAlias,
		KeyHash:     firstNonEmpty(wr.APIKey, wr.Metadata.UserAPIKey),
		TeamID:      firstNonEmpty(wr.TeamID, wr.Metadata.UserAPIKeyTeamID),
		Provider:    wr.CustomLLMProvider,
		CallType:    wr.CallType,
		RequesterIP: firstNonEmpty(wr.RequesterIPAddress, wr.Metadata.RequesterIPAddress),
	}
	if wr.Metadata.AttemptedRetries != nil {
		n := *wr.Metadata.AttemptedRetries
		gw.AttemptedRetries = &n
	}

	ev := &model.LLMEvent{
		Source:       model.SourceLiteLLM,
		Tags:         cleanRequestTags(wr.RequestTags),
		Gateway:      gw,
		SourceRecord: append([]byte(nil), line...),
	}

	// The join key. Absent is a real, expected state -- every request made
	// before cmd/wiretap began sending spend_logs_metadata has none -- so
	// it is left empty rather than substituted, and join-health reporting
	// is what surfaces it. See docs/CORRELATION.md and join-baseline.json.
	if id, ok := wr.traceID(); ok {
		ev.TraceID = id
	}
	// Deliberately NOT session_id: on a refused request LiteLLM discards
	// the caller's value and substitutes a random UUID, so carrying it
	// would populate session.id with a different meaning depending on
	// whether the request succeeded. Only trust it on a success.
	if wr.Status == statusSuccess {
		ev.SessionID = wr.SessionID
	}
	ev.UserID = firstNonEmpty(wr.EndUser, wr.User, wr.Metadata.UserAPIKeyUserID)

	ev.RequestTimestamp = parseGatewayTime(wr.StartTime)
	ev.StartTime = ev.RequestTimestamp
	ev.EndTime = parseGatewayTime(wr.EndTime)
	if wr.RequestDurationMs > 0 {
		d := time.Duration(wr.RequestDurationMs) * time.Millisecond
		ev.Duration = &d
	}

	applyGatewayStatus(ev, &wr)
	applyGatewayModels(ev, &wr)
	applyGatewayUsage(ev, &wr)

	return ev, nil
}

const (
	statusSuccess = "success"
	statusFailure = "failure"
)

// applyGatewayStatus maps LiteLLM's own status vocabulary onto
// model.Status, and lifts the structured error detail that is the gateway
// plane's headline contribution.
func applyGatewayStatus(ev *model.LLMEvent, wr *wireSpendLog) {
	switch wr.Status {
	case statusSuccess:
		ev.Status = model.StatusSuccess
	case statusFailure:
		ev.Status = model.StatusFailure
	default:
		// An unrecognised status is genuinely unknown, not a failure.
		// Guessing here would let a future LiteLLM status value silently
		// become "everything is fine" or "everything is broken."
		ev.Status = model.StatusUnknown
	}

	ei := wr.Metadata.ErrorInformation
	if ei == nil {
		return
	}
	ev.StatusMessage = ei.ErrorMessage
	ev.Gateway.ErrorClass = ei.ErrorClass
	ev.Gateway.ErrorCode = ei.ErrorCode

	// error_code is a string on the wire ("429"). Parse it into a real
	// status code only when it genuinely is one -- a non-numeric code is
	// kept as ErrorCode and simply yields no HTTP status, rather than a
	// fabricated 0 that would read as "the request returned zero."
	if code, ok := parseHTTPStatus(ei.ErrorCode); ok {
		ev.Gateway.HTTPStatusCode = &code
	}
}

// applyGatewayModels routes the polymorphic model field. On success
// LiteLLM's `model` is the model that *served* the request,
// provider-prefixed; on a refusal nothing served it, so the same field
// holds the model the caller *requested*, unprefixed. Mapping it
// unconditionally to the served model would claim a model answered a
// request it rejected -- the same error the content-plane parser had to
// fix for ERROR-level observations.
func applyGatewayModels(ev *model.LLMEvent, wr *wireSpendLog) {
	// model_group is LiteLLM's own name for "what the caller asked for"
	// and is authoritative when present. It is "" on a refusal.
	ev.RequestModel = wr.ModelGroup

	if ev.Status == model.StatusFailure {
		if ev.RequestModel == "" {
			ev.RequestModel = wr.Model
		}
		return
	}
	ev.ResponseModel = wr.Model
	if ev.RequestModel == "" {
		ev.RequestModel = wr.Model
	}
	// On success LiteLLM sets request_id to the provider's completion ID.
	// Only then is it one; on a refusal it is an unrelated UUID and must
	// not be presented as a completion.
	if strings.HasPrefix(wr.RequestID, completionIDPrefix) {
		ev.ResponseID = wr.RequestID
	}
}

// completionIDPrefix is how OpenAI-compatible providers prefix a chat
// completion ID. LiteLLM reuses the provider's value as request_id on a
// successful record, so the prefix is what distinguishes "this is a real
// completion ID" from "this is LiteLLM's own UUID for an attempt that
// never produced one."
const completionIDPrefix = "chatcmpl-"

// applyGatewayUsage sets token counts and cost only when LiteLLM says it
// actually has them. See ParseGatewayLine's doc comment: the top-level
// numeric fields are NOT NULL columns that read zero on a request that
// never ran, and usage_object/cost_breakdown being null is LiteLLM's own
// statement that there is nothing to report.
func applyGatewayUsage(ev *model.LLMEvent, wr *wireSpendLog) {
	if jsonPresent(wr.Metadata.UsageObject) {
		in, out := wr.PromptTokens, wr.CompletionTokens
		ev.InputTokens = &in
		ev.OutputTokens = &out
	}
	if jsonPresent(wr.Metadata.CostBreakdown) {
		cost := wr.Spend
		ev.TotalCost = &cost
	}
}

// jsonPresent reports whether raw holds an actual JSON value, as opposed
// to being absent or an explicit null.
//
// This is not a stylistic nicety. json.RawMessage is a []byte, and
// unmarshalling a JSON `null` into one yields the four bytes "null" --
// which is non-nil and length 4. A plain `!= nil` check therefore reports
// "present" for exactly the records LiteLLM uses null to mean "I have no
// usage data for this request", which would have restored the
// blocked-request-looks-free bug through a completely different door.
// Caught by TestParseGatewayLine_RealRecords rather than by review.
func jsonPresent(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// wireSpendLog mirrors the fields of one /spend/logs/v2 record this parser
// reads. As with wireTrace, everything else is silently dropped by
// encoding/json, which is correct for fields nothing downstream needs --
// notably metadata.model_map_information, a ~90-key static pricing table
// repeated verbatim on every single record.
//
// This deliberately does not import internal/litellm's SpendLog, for the
// same reason internal/parse does not import internal/langfuse: this
// package decodes raw archive bytes, which may have been written months
// ago by a different version of the client, not typed API responses from
// the client as it exists today.
type wireSpendLog struct {
	RequestID string `json:"request_id"`
	CallType  string `json:"call_type"`
	// APIKey is the SHA-256 hash of the virtual key, never the key.
	APIKey string `json:"api_key"`

	Spend            float64 `json:"spend"`
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`

	StartTime         string `json:"startTime"`
	EndTime           string `json:"endTime"`
	RequestDurationMs int    `json:"request_duration_ms"`

	Model             string `json:"model"`
	ModelGroup        string `json:"model_group"`
	CustomLLMProvider string `json:"custom_llm_provider"`

	User               string   `json:"user"`
	EndUser            string   `json:"end_user"`
	TeamID             string   `json:"team_id"`
	SessionID          string   `json:"session_id"`
	RequesterIPAddress string   `json:"requester_ip_address"`
	RequestTags        []string `json:"request_tags"`
	Status             string   `json:"status"`

	Metadata wireSpendLogMetadata `json:"metadata"`
}

type wireSpendLogMetadata struct {
	SpendLogsMetadata map[string]json.RawMessage `json:"spend_logs_metadata"`

	UserAPIKeyAlias  string `json:"user_api_key_alias"`
	UserAPIKey       string `json:"user_api_key"`
	UserAPIKeyUserID string `json:"user_api_key_user_id"`
	UserAPIKeyTeamID string `json:"user_api_key_team_id"`

	LiteLLMCallID      string `json:"litellm_call_id"`
	RequesterIPAddress string `json:"requester_ip_address"`

	ErrorInformation *wireErrorInformation `json:"error_information"`

	// UsageObject and CostBreakdown are decoded only to learn whether they
	// are null. Their contents duplicate the top-level token and cost
	// fields; their *presence* is the thing this parser needs, and is the
	// only honest way to tell a measured zero from a schema default.
	UsageObject   json.RawMessage `json:"usage_object"`
	CostBreakdown json.RawMessage `json:"cost_breakdown"`

	AttemptedRetries *int `json:"attempted_retries"`
}

type wireErrorInformation struct {
	ErrorCode    string `json:"error_code"`
	ErrorClass   string `json:"error_class"`
	ErrorMessage string `json:"error_message"`
	// Traceback is deliberately not decoded: it is LiteLLM's internal file
	// paths, with no analytic value and real storage cost.
}

// traceID returns the caller-supplied join key from
// metadata.spend_logs_metadata.trace_id.
//
// spend_logs_metadata is an arbitrary caller-controlled map, so this
// decodes defensively: a non-string trace_id, an empty one, or a missing
// key all report absent rather than yielding "" as though it were an ID.
// An empty string used as a join key is precisely the failure this project
// has already paid for once.
func (w wireSpendLog) traceID() (string, bool) {
	raw, ok := w.Metadata.SpendLogsMetadata["trace_id"]
	if !ok {
		return "", false
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil {
		return "", false
	}
	if id == "" {
		return "", false
	}
	return id, true
}

// parseGatewayTime accepts the timestamp forms /spend/logs/v2 emits.
// Verified against live responses: v2 returns "2026-07-30T23:05:07.138+00:00"
// while the older /spend/logs returns "2026-07-30T23:05:07.138000Z". Both
// are RFC3339, but an archive may contain lines written by either, so both
// must parse. A zero time is returned for anything else rather than an
// error: one unparseable timestamp is not a reason to discard an otherwise
// usable enforcement record.
func parseGatewayTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	// LiteLLM has also been observed emitting a naive timestamp with no
	// zone at all on some routes. Interpret as UTC, which is what the
	// database stores.
	if t, err := time.Parse("2006-01-02T15:04:05.999999", s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// parseHTTPStatus converts LiteLLM's string error_code into a status code,
// reporting false for anything outside the valid HTTP range rather than
// returning a number that would be indexed as a real status.
func parseHTTPStatus(code string) (int, bool) {
	if len(code) != 3 {
		return 0, false
	}
	n := 0
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n < 100 || n > 599 {
		return 0, false
	}
	return n, true
}

// userAgentTagPrefix marks the pseudo-tags LiteLLM synthesises from the
// caller's User-Agent header and mixes into request_tags alongside the
// caller's real tags. They are not tags anyone applied and would pollute a
// tag-based query, so they are dropped -- the User-Agent is still visible
// in the archived raw record for anyone who wants it.
const userAgentTagPrefix = "User-Agent:"

func cleanRequestTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if strings.HasPrefix(t, userAgentTagPrefix) {
			continue
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ParseGatewayLines parses a whole NDJSON buffer, one spend record per
// line, skipping blank lines. It returns every event it could parse plus
// every error it hit, rather than stopping at the first bad line: one
// corrupt record in an archive must not cost every record after it. Line
// numbers are 1-based and count blank lines, so an error's Line matches
// what an editor shows.
func ParseGatewayLines(data []byte) ([]*model.LLMEvent, []error) {
	var events []*model.LLMEvent
	var errs []error
	for i, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		ev, err := ParseGatewayLine(line, i+1)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		events = append(events, ev)
	}
	return events, errs
}
