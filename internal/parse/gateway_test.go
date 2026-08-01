package parse

import (
	"errors"
	"strings"
	"testing"

	"wiretap/internal/model"
)

// TestParseGatewayLine_RealRecords is the table-driven core of the gateway
// parser's coverage. Every fixture is a real /spend/logs/v2 record from a
// live LiteLLM 1.93.0 proxy, with virtual-key SHA-256 hashes remapped onto
// obvious fakes and metadata.model_map_information (a ~90-key static
// pricing table repeated on every record) dropped. Nothing else was
// edited.
//
// The four outcomes are not variations on a theme: a successful record and
// a refused one are genuinely different shapes, and the assertions below
// are mostly about the fields that exist in one and not the other.
func TestParseGatewayLine_RealRecords(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture string

		wantStatus     model.Status
		wantErrorClass string
		wantHTTPStatus int // 0 means "must be absent"
		wantMsgSubstr  string

		wantUsagePresent bool
		wantCostPresent  bool

		wantResponseModel string // "" means must be absent
		wantRequestModel  string
		wantResponseIDPfx string // "" means must be absent
		wantProvider      string

		wantKeyAlias   string
		wantKeyHashSet bool
		wantTraceID    string
	}{
		{
			name:    "successful request",
			fixture: "gateway_success",

			wantStatus:       model.StatusSuccess,
			wantUsagePresent: true,
			wantCostPresent:  true,

			wantResponseModel: "groq/llama-3.3-70b-versatile",
			wantRequestModel:  "llama-3.3-70b-versatile",
			wantResponseIDPfx: "chatcmpl-",
			wantProvider:      "groq",

			wantKeyHashSet: true,
			wantTraceID:    "benign-d04b73554231370f4f15c9293bfdbae3",
		},
		{
			name:    "budget block",
			fixture: "gateway_budget_block",

			wantStatus:     model.StatusFailure,
			wantErrorClass: "BudgetExceededError",
			wantHTTPStatus: 429,
			wantMsgSubstr:  "Budget has been exceeded",

			// The record reports spend 0.0 and prompt_tokens 0. Neither is
			// a measurement; usage_object and cost_breakdown are null.
			wantUsagePresent: false,
			wantCostPresent:  false,

			// Nothing served it, so no response model and no completion.
			// The unprefixed model on the record is what was *requested*.
			wantResponseModel: "",
			wantRequestModel:  "llama-3.3-70b-versatile",
			wantResponseIDPfx: "",
			wantProvider:      "",

			wantKeyAlias:   "probe-budget-1",
			wantKeyHashSet: true,
			wantTraceID:    "probe-fill5-b967a34767bf",
		},
		{
			name:    "auth failure",
			fixture: "gateway_auth_failure",

			wantStatus:     model.StatusFailure,
			wantErrorClass: "KeyNotFoundError",
			wantHTTPStatus: 401,
			wantMsgSubstr:  "Authentication Error",

			wantUsagePresent: false,
			wantCostPresent:  false,

			wantResponseModel: "",
			wantRequestModel:  "llama-3.3-70b-versatile",
			wantResponseIDPfx: "",
			wantProvider:      "",

			// No alias: there is no name for a key that never existed.
			// The attempted key's hash is still recorded, and is the only
			// thing a credential-spray detection can cluster on.
			wantKeyAlias:   "",
			wantKeyHashSet: true,
			wantTraceID:    "probe-authfail-b469cbc39f389eea",
		},
		{
			name:    "rate limited",
			fixture: "gateway_rate_limited",

			wantStatus: model.StatusFailure,
			// Same HTTP status as the budget block. Different class. This
			// is the case that proves error.code alone cannot tell
			// enforcement types apart and error.type is load-bearing.
			wantErrorClass: "ProxyRateLimitError",
			wantHTTPStatus: 429,
			wantMsgSubstr:  "Rate limit exceeded",

			wantUsagePresent: false,
			wantCostPresent:  false,

			wantResponseModel: "",
			wantRequestModel:  "llama-3.3-70b-versatile",
			wantResponseIDPfx: "",
			wantProvider:      "",

			wantKeyAlias:   "probe-rpm-1",
			wantKeyHashSet: true,
			wantTraceID:    "probe-rpm2-3c3729dfba38",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := ParseGatewayLine(readFixture(t, tc.fixture+".json"), 1)
			if err != nil {
				t.Fatalf("ParseGatewayLine: %v", err)
			}
			if ev.Source != model.SourceLiteLLM {
				t.Errorf("Source = %q, want %q", ev.Source, model.SourceLiteLLM)
			}
			if ev.Gateway == nil {
				t.Fatal("Gateway is nil; a gateway event must carry gateway detail")
			}

			if ev.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", ev.Status, tc.wantStatus)
			}
			if ev.Gateway.ErrorClass != tc.wantErrorClass {
				t.Errorf("ErrorClass = %q, want %q", ev.Gateway.ErrorClass, tc.wantErrorClass)
			}
			if tc.wantHTTPStatus == 0 {
				if ev.Gateway.HTTPStatusCode != nil {
					t.Errorf("HTTPStatusCode = %d, want absent", *ev.Gateway.HTTPStatusCode)
				}
			} else {
				if ev.Gateway.HTTPStatusCode == nil {
					t.Errorf("HTTPStatusCode is absent, want %d", tc.wantHTTPStatus)
				} else if *ev.Gateway.HTTPStatusCode != tc.wantHTTPStatus {
					t.Errorf("HTTPStatusCode = %d, want %d", *ev.Gateway.HTTPStatusCode, tc.wantHTTPStatus)
				}
			}
			if tc.wantMsgSubstr != "" && !strings.Contains(ev.StatusMessage, tc.wantMsgSubstr) {
				t.Errorf("StatusMessage = %q, want it to contain %q", ev.StatusMessage, tc.wantMsgSubstr)
			}

			// Absent-not-zero, the whole point of this parser.
			if (ev.InputTokens != nil) != tc.wantUsagePresent {
				t.Errorf("InputTokens present = %v, want %v -- the record's prompt_tokens field reads 0 either way", ev.InputTokens != nil, tc.wantUsagePresent)
			}
			if (ev.OutputTokens != nil) != tc.wantUsagePresent {
				t.Errorf("OutputTokens present = %v, want %v", ev.OutputTokens != nil, tc.wantUsagePresent)
			}
			if (ev.TotalCost != nil) != tc.wantCostPresent {
				t.Errorf("TotalCost present = %v, want %v -- the record's spend field reads 0.0 either way", ev.TotalCost != nil, tc.wantCostPresent)
			}

			if ev.ResponseModel != tc.wantResponseModel {
				t.Errorf("ResponseModel = %q, want %q", ev.ResponseModel, tc.wantResponseModel)
			}
			if ev.RequestModel != tc.wantRequestModel {
				t.Errorf("RequestModel = %q, want %q", ev.RequestModel, tc.wantRequestModel)
			}
			if tc.wantResponseIDPfx == "" {
				if ev.ResponseID != "" {
					t.Errorf("ResponseID = %q, want absent -- a refused request produced no completion", ev.ResponseID)
				}
			} else if !strings.HasPrefix(ev.ResponseID, tc.wantResponseIDPfx) {
				t.Errorf("ResponseID = %q, want prefix %q", ev.ResponseID, tc.wantResponseIDPfx)
			}
			if ev.Gateway.Provider != tc.wantProvider {
				t.Errorf("Provider = %q, want %q", ev.Gateway.Provider, tc.wantProvider)
			}

			if ev.Gateway.KeyAlias != tc.wantKeyAlias {
				t.Errorf("KeyAlias = %q, want %q", ev.Gateway.KeyAlias, tc.wantKeyAlias)
			}
			if (ev.Gateway.KeyHash != "") != tc.wantKeyHashSet {
				t.Errorf("KeyHash present = %v, want %v", ev.Gateway.KeyHash != "", tc.wantKeyHashSet)
			}
			if ev.TraceID != tc.wantTraceID {
				t.Errorf("TraceID = %q, want %q", ev.TraceID, tc.wantTraceID)
			}

			// Timing: both boundaries, and event.start is what correlates.
			if ev.StartTime.IsZero() {
				t.Error("StartTime is zero; cross-plane correlation compares it")
			}
			if ev.EndTime.IsZero() {
				t.Error("EndTime is zero")
			}
			if !ev.RequestTimestamp.Equal(ev.StartTime) {
				t.Errorf("RequestTimestamp = %v, want it to equal StartTime %v for this source", ev.RequestTimestamp, ev.StartTime)
			}

			// Provenance: the raw record is kept verbatim for replay.
			if len(ev.SourceRecord) == 0 {
				t.Error("SourceRecord is empty; replay and debugging depend on it")
			}
		})
	}
}

// TestParseGatewayLine_RetriesShareOneTraceID is the fixture behind the
// retry-inflation caveat in docs/DETECTIONS.md. One logical request that
// the client retried three times produces three gateway records -- three
// distinct request_ids, three distinct call IDs, one shared trace ID.
//
// A rule that counts gateway documents reports three enforcement events
// where a user experienced one. Counting distinct trace IDs is what makes
// it one, and this test pins the property that makes that possible.
func TestParseGatewayLine_RetriesShareOneTraceID(t *testing.T) {
	events, errs := ParseGatewayLines(readFixture(t, "gateway_retries.ndjson"))
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(events) != 3 {
		t.Fatalf("parsed %d events, want 3 (one per HTTP attempt)", len(events))
	}

	traceIDs := map[string]int{}
	requestIDs := map[string]bool{}
	callIDs := map[string]bool{}
	for _, ev := range events {
		traceIDs[ev.TraceID]++
		requestIDs[ev.Gateway.RequestID] = true
		callIDs[ev.Gateway.CallID] = true

		if ev.Status != model.StatusFailure {
			t.Errorf("attempt has Status %q, want failure", ev.Status)
		}
		if ev.InputTokens != nil || ev.TotalCost != nil {
			t.Error("a refused attempt reported usage or cost")
		}
	}

	if len(traceIDs) != 1 {
		t.Errorf("got %d distinct trace IDs across retries, want 1: %v", len(traceIDs), traceIDs)
	}
	if len(requestIDs) != 3 {
		t.Errorf("got %d distinct request IDs, want 3 -- each attempt is its own gateway record", len(requestIDs))
	}
	if len(callIDs) != 3 {
		t.Errorf("got %d distinct call IDs, want 3", len(callIDs))
	}

	// The ordering property a fetch checkpoint relies on.
	for i := 1; i < len(events); i++ {
		if events[i].StartTime.Before(events[i-1].StartTime) {
			t.Error("retry attempts are not in ascending start order")
		}
	}
}

// TestParseGatewayLine_MalformedReturnsLineError checks the error carries
// enough to find the bad record in a multi-megabyte archive: which line,
// and what it looked like.
func TestParseGatewayLine_MalformedReturnsLineError(t *testing.T) {
	_, err := ParseGatewayLine(readFixture(t, "gateway_malformed.json"), 42)
	if err == nil {
		t.Fatal("expected an error for a truncated record")
	}
	var le *LineError
	if !errors.As(err, &le) {
		t.Fatalf("error is %T, want *LineError", err)
	}
	if le.Line != 42 {
		t.Errorf("LineError.Line = %d, want 42", le.Line)
	}
	if le.Excerpt == "" {
		t.Error("LineError.Excerpt is empty; a bare 'invalid JSON' is not debuggable")
	}
	if len(le.Excerpt) > excerptLen+3 {
		t.Errorf("excerpt is %d chars, want it truncated to ~%d", len(le.Excerpt), excerptLen)
	}
}

func TestParseGatewayLine_MissingRequestIDReturnsLineError(t *testing.T) {
	_, err := ParseGatewayLine([]byte(`{"status":"success"}`), 7)
	var le *LineError
	if !errors.As(err, &le) {
		t.Fatalf("error is %T, want *LineError", err)
	}
	if le.Line != 7 {
		t.Errorf("LineError.Line = %d, want 7", le.Line)
	}
}

// TestParseGatewayLines_OneBadLineDoesNotCostTheRest is the archive
// robustness property: a partial write in the middle of a file must not
// discard every record after it.
func TestParseGatewayLines_OneBadLineDoesNotCostTheRest(t *testing.T) {
	good := readFixture(t, "gateway_success.json")
	// Fixtures are pretty-printed; collapse to one line for NDJSON.
	oneLine := strings.Join(strings.Fields(string(good)), "")

	data := []byte(oneLine + "\n" + `{"truncated":` + "\n" + oneLine + "\n")
	events, errs := ParseGatewayLines(data)

	if len(events) != 2 {
		t.Errorf("parsed %d events, want 2 (the bad line in the middle must not stop the rest)", len(events))
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1", len(errs))
	}
	var le *LineError
	if !errors.As(errs[0], &le) || le.Line != 2 {
		t.Errorf("error = %v, want a *LineError on line 2", errs[0])
	}
}

// TestParseGatewayLine_NullSafety feeds shapes that a field-present-in-one-
// sample assumption would crash or lie on. None of these may panic, and
// none may invent a value.
func TestParseGatewayLine_NullSafety(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"only a request_id", `{"request_id":"r1"}`},
		{"null metadata", `{"request_id":"r1","metadata":null}`},
		{"null error_information", `{"request_id":"r1","status":"failure","metadata":{"error_information":null}}`},
		{"null spend_logs_metadata", `{"request_id":"r1","metadata":{"spend_logs_metadata":null}}`},
		{"null request_tags", `{"request_id":"r1","request_tags":null}`},
		{"empty timestamps", `{"request_id":"r1","startTime":"","endTime":""}`},
		{"garbage timestamps", `{"request_id":"r1","startTime":"not-a-time","endTime":"also-not"}`},
		{"unknown status", `{"request_id":"r1","status":"quiesced"}`},
		{"non-string trace_id", `{"request_id":"r1","metadata":{"spend_logs_metadata":{"trace_id":42}}}`},
		{"non-numeric error_code", `{"request_id":"r1","status":"failure","metadata":{"error_information":{"error_code":"boom"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := ParseGatewayLine([]byte(tc.raw), 1)
			if err != nil {
				t.Fatalf("ParseGatewayLine: %v", err)
			}
			// Nothing may be invented from absence.
			if ev.InputTokens != nil || ev.OutputTokens != nil || ev.TotalCost != nil {
				t.Error("usage or cost was populated from a record that reported neither")
			}
			if ev.TraceID != "" && tc.name == "non-string trace_id" {
				t.Errorf("TraceID = %q, want empty for a non-string trace_id", ev.TraceID)
			}
			if tc.name == "non-numeric error_code" && ev.Gateway.HTTPStatusCode != nil {
				t.Errorf("HTTPStatusCode = %d, want absent for a non-numeric error_code", *ev.Gateway.HTTPStatusCode)
			}
			if tc.name == "unknown status" && ev.Status != model.StatusUnknown {
				t.Errorf("Status = %q, want unknown for an unrecognised status value", ev.Status)
			}
			if tc.name == "garbage timestamps" && !ev.StartTime.IsZero() {
				t.Error("StartTime was populated from an unparseable timestamp")
			}
		})
	}
}

// TestParseGatewayLine_SessionIDOnlyTrustedOnSuccess pins a specific trap.
// On a refused request LiteLLM discards the caller's session_id and writes
// a fresh random UUID, so carrying it through unconditionally would give
// session.id two different meanings depending on outcome -- and would make
// "group this session's requests" silently wrong exactly where enforcement
// happened.
func TestParseGatewayLine_SessionIDOnlyTrustedOnSuccess(t *testing.T) {
	ok, err := ParseGatewayLine([]byte(`{"request_id":"chatcmpl-1","status":"success","session_id":"module4"}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	if ok.SessionID != "module4" {
		t.Errorf("SessionID = %q, want the caller's value on a success", ok.SessionID)
	}

	bad, err := ParseGatewayLine([]byte(`{"request_id":"u1","status":"failure","session_id":"b3defaac-bb27-4909-bf76-86d9c6b98c7c"}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	if bad.SessionID != "" {
		t.Errorf("SessionID = %q, want empty on a failure -- LiteLLM's value there is a random UUID, not the caller's session", bad.SessionID)
	}
}

// TestParseGatewayLine_DropsUserAgentPseudoTags confirms the synthetic
// tags LiteLLM mixes into request_tags do not reach the tags field, where
// they would pollute every tag-based query.
func TestParseGatewayLine_DropsUserAgentPseudoTags(t *testing.T) {
	ev, err := ParseGatewayLine([]byte(`{"request_id":"r1","request_tags":["wiretap","benign","User-Agent: OpenAI","User-Agent: OpenAI/Go 3.44.0"]}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"wiretap", "benign"}
	if len(ev.Tags) != len(want) {
		t.Fatalf("Tags = %v, want %v", ev.Tags, want)
	}
	for i := range want {
		if ev.Tags[i] != want[i] {
			t.Errorf("Tags = %v, want %v", ev.Tags, want)
		}
	}
}

// TestParseGatewayLine_MissingJoinKeyIsAbsentNotInvented covers the
// pre-client-change records enumerated in join-baseline.json. Their
// absence of a join key is a real, expected state and must read as empty
// rather than as some substitute that would appear to correlate.
func TestParseGatewayLine_MissingJoinKeyIsAbsentNotInvented(t *testing.T) {
	ev, err := ParseGatewayLine([]byte(`{"request_id":"chatcmpl-abc","status":"success","session_id":"module4","metadata":{"litellm_call_id":"c1"}}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	if ev.TraceID != "" {
		t.Errorf("TraceID = %q, want empty -- no join key was sent, and inventing one from session_id or call_id would fabricate correlations", ev.TraceID)
	}
}

// TestParseGatewayLine_HealthCheck asserts the gateway plane recognises
// LiteLLM's own health-check rows, which the content plane has always
// recognised by trace tag.
//
// The fixture is a real /spend/logs/v2 record produced by hitting the
// proxy's own GET /health. Note what it is *not* distinguishable by:
// call_type is a plain "acompletion", status is "success", and both
// usage_object and cost_breakdown are populated -- it really did reach
// Groq and really did cost money. What it has instead is a null
// spend_logs_metadata, hence no join key, which is exactly why leaving
// these in the gateway index puts a permanent floor under join health's
// without-join-key count.
func TestParseGatewayLine_HealthCheck(t *testing.T) {
	ev, err := ParseGatewayLine(readFixture(t, "gateway_health_check.json"), 1)
	if err != nil {
		t.Fatalf("ParseGatewayLine: %v", err)
	}
	if !ev.IsHealthCheck {
		t.Error("IsHealthCheck = false, want true")
	}
	if ev.TraceID != "" {
		t.Errorf("TraceID = %q, want empty -- a health check carries no spend_logs_metadata", ev.TraceID)
	}
	if ev.Status != model.StatusSuccess {
		t.Errorf("Status = %v, want success -- a health check is a real request that really ran", ev.Status)
	}
	if ev.InputTokens == nil || ev.OutputTokens == nil {
		t.Error("usage is absent, want present -- the fixture has a real usage_object, and treating it as absent would hide that these rows cost money")
	}
}

// TestParseGatewayLine_HealthCheckStamps pins the asymmetry between
// LiteLLM's two stamps.
//
// The "request tag alone" case is the load-bearing one, and it asserts a
// *negative*: request_tags is caller-supplied, so a record carrying only
// the tag is not evidence of a health check, it is evidence of something
// claiming to be one. Honouring it would let any caller drop itself out of
// a security index by naming a string. A forged tag instead leaves the
// record here and removed on the content plane, and that disagreement is
// what makes it show up as gateway_unexplained. An earlier revision
// treated the tag as sufficient and silently closed that window; this test
// is what stops it coming back.
func TestParseGatewayLine_HealthCheckStamps(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "request tag alone is not sufficient",
			raw:  `{"request_id":"r1","request_tags":["litellm-internal-health-check"],"metadata":{}}`,
			want: false,
		},
		{
			name: "spoofed tag on otherwise ordinary caller traffic",
			raw: `{"request_id":"chatcmpl-abc","call_type":"acompletion","api_key":"deadbeef",` +
				`"request_tags":["litellm-internal-health-check"],"metadata":` +
				`{"user_api_key_alias":"wiretap-main","spend_logs_metadata":{"trace_id":"benign-1"}}}`,
			want: false,
		},
		{
			name: "service account key alias alone",
			raw:  `{"request_id":"r1","metadata":{"user_api_key_alias":"litellm-internal-health-check"}}`,
			want: true,
		},
		{
			name: "service account api key alone",
			raw:  `{"request_id":"r1","api_key":"litellm-internal-health-check","metadata":{}}`,
			want: true,
		},
		{
			name: "service account team alone",
			raw:  `{"request_id":"r1","team_id":"litellm-internal-health-check","metadata":{}}`,
			want: true,
		},
		{
			name: "ordinary traffic",
			raw:  `{"request_id":"chatcmpl-abc","call_type":"acompletion","api_key":"deadbeef","request_tags":["wiretap","benign"],"metadata":{"user_api_key_alias":"wiretap-main"}}`,
			want: false,
		},
		{
			name: "null everywhere",
			raw:  `{"request_id":"r1","request_tags":null,"api_key":null,"team_id":null,"metadata":null}`,
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := ParseGatewayLine([]byte(tc.raw), 1)
			if err != nil {
				t.Fatalf("ParseGatewayLine: %v", err)
			}
			if ev.IsHealthCheck != tc.want {
				t.Errorf("IsHealthCheck = %v, want %v", ev.IsHealthCheck, tc.want)
			}
		})
	}
}

// TestParseGatewayLine_NullTraceIDValueIsAbsent covers the nested form of
// the null trap. spend_logs_metadata is map[string]json.RawMessage, so a
// null *value* under the trace_id key yields the four bytes "null" rather
// than a missing entry -- the key is present, the RawMessage is non-nil,
// and only unmarshalling it reveals there is nothing there. Unmarshalling
// "null" into a string succeeds and leaves "", so the empty-string guard
// in traceID is what actually stops an empty join key getting through.
func TestParseGatewayLine_NullTraceIDValueIsAbsent(t *testing.T) {
	for _, raw := range []string{
		`{"request_id":"r1","metadata":{"spend_logs_metadata":{"trace_id":null}}}`,
		`{"request_id":"r1","metadata":{"spend_logs_metadata":{"trace_id":""}}}`,
		`{"request_id":"r1","metadata":{"spend_logs_metadata":{}}}`,
	} {
		ev, err := ParseGatewayLine([]byte(raw), 1)
		if err != nil {
			t.Fatalf("ParseGatewayLine(%s): %v", raw, err)
		}
		if ev.TraceID != "" {
			t.Errorf("TraceID = %q for %s, want empty -- an empty join key must never read as a valid one", ev.TraceID, raw)
		}
	}
}
