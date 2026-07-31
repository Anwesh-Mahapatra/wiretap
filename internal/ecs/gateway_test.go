package ecs

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wiretap/internal/model"
	"wiretap/internal/parse"
)

var fixedGatewayCfg = DefaultGatewayConfig()

func mapGatewayFixture(t *testing.T, name string) (*model.LLMEvent, *Document) {
	t.Helper()
	ev, err := parse.ParseGatewayLine(loadRaw(t, name), 1)
	if err != nil {
		t.Fatalf("parsing gateway fixture %q: %v", name, err)
	}
	return ev, MapGateway(ev, fixedGatewayCfg)
}

var gatewayFixtures = []string{
	"gateway_success",
	"gateway_budget_block",
	"gateway_auth_failure",
	"gateway_rate_limited",
}

// TestMapGateway_GoldenFiles pins the full document for every gateway
// fixture, byte for byte. Same discipline as the content plane's golden
// test: MapGateway is pure, so its output is stable, and any change to any
// field shows up as a reviewable diff rather than as a surprise in
// Elasticsearch three weeks later.
func TestMapGateway_GoldenFiles(t *testing.T) {
	for _, name := range gatewayFixtures {
		t.Run(name, func(t *testing.T) {
			_, doc := mapGatewayFixture(t, name)

			got, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatalf("marshaling document: %v", err)
			}
			got = append(got, '\n')

			goldenPath := filepath.Join("testdata", "golden", name+".json")
			if *update {
				if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
					t.Fatalf("writing golden file: %v", err)
				}
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("reading golden file %q: %v (run with -update to generate it)", goldenPath, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("MapGateway(%s) does not match golden file %s.\n--- got ---\n%s\n--- want ---\n%s", name, goldenPath, got, want)
			}
		})
	}
}

// TestMapGateway_EnforcementFieldsPerFixture asserts the specific
// gateway-only facts each fixture is here to carry, in a form that names
// what is being checked rather than relying on a golden diff to be read
// carefully.
func TestMapGateway_EnforcementFieldsPerFixture(t *testing.T) {
	for _, tc := range []struct {
		fixture string

		wantOutcome    string
		wantTypes      []string
		wantCategories []string
		wantAction     string
		wantStatusCode int // 0 = must be absent
		wantErrorType  string
		wantErrorCode  string
		wantKeyAlias   string
	}{
		{
			fixture:        "gateway_success",
			wantOutcome:    "success",
			wantTypes:      []string{"allowed"},
			wantCategories: []string{"api"},
			wantAction:     "chat_completion",
			wantStatusCode: 0,
		},
		{
			fixture:        "gateway_budget_block",
			wantOutcome:    "failure",
			wantTypes:      []string{"denied"},
			wantCategories: []string{"api"},
			wantAction:     "budget_exceeded",
			wantStatusCode: 429,
			wantErrorType:  "BudgetExceededError",
			wantErrorCode:  "429",
			wantKeyAlias:   "probe-budget-1",
		},
		{
			fixture: "gateway_rate_limited",
			// Same HTTP status as the budget block above, different action
			// and different error.type. This pair is the whole argument
			// for carrying error.type at all.
			wantOutcome:    "failure",
			wantTypes:      []string{"denied"},
			wantCategories: []string{"api"},
			wantAction:     "rate_limited",
			wantStatusCode: 429,
			wantErrorType:  "ProxyRateLimitError",
			wantErrorCode:  "429",
			wantKeyAlias:   "probe-rpm-1",
		},
		{
			fixture:     "gateway_auth_failure",
			wantOutcome: "failure",
			// "start" accompanies "denied" because the authentication
			// category expects start/end/info, and a rejected credential
			// is the start of a challenge-and-response exchange.
			wantTypes:      []string{"denied", "start"},
			wantCategories: []string{"api", "authentication"},
			wantAction:     "auth_failure",
			wantStatusCode: 401,
			wantErrorType:  "KeyNotFoundError",
			wantErrorCode:  "401",
			// No alias: there is no name for a key that never existed.
			wantKeyAlias: "",
		},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			_, doc := mapGatewayFixture(t, tc.fixture)

			if doc.Event.Dataset != DatasetLiteLLM {
				t.Errorf("event.dataset = %q, want %q", doc.Event.Dataset, DatasetLiteLLM)
			}
			if doc.Event.Outcome != tc.wantOutcome {
				t.Errorf("event.outcome = %q, want %q", doc.Event.Outcome, tc.wantOutcome)
			}
			if !equalStrings(doc.Event.Type, tc.wantTypes) {
				t.Errorf("event.type = %v, want %v", doc.Event.Type, tc.wantTypes)
			}
			if !equalStrings(doc.Event.Category, tc.wantCategories) {
				t.Errorf("event.category = %v, want %v", doc.Event.Category, tc.wantCategories)
			}
			if doc.Event.Action != tc.wantAction {
				t.Errorf("event.action = %q, want %q", doc.Event.Action, tc.wantAction)
			}

			if tc.wantStatusCode == 0 {
				if doc.HTTP != nil {
					t.Errorf("http = %+v, want absent on a successful request", doc.HTTP)
				}
			} else {
				if doc.HTTP == nil || doc.HTTP.Response == nil || doc.HTTP.Response.StatusCode == nil {
					t.Fatalf("http.response.status_code is absent, want %d", tc.wantStatusCode)
				}
				if got := *doc.HTTP.Response.StatusCode; got != tc.wantStatusCode {
					t.Errorf("http.response.status_code = %d, want %d", got, tc.wantStatusCode)
				}
			}

			if tc.wantErrorType == "" {
				if doc.Error != nil {
					t.Errorf("error = %+v, want absent", doc.Error)
				}
			} else {
				if doc.Error == nil {
					t.Fatal("error object is absent")
				}
				if doc.Error.Type != tc.wantErrorType {
					t.Errorf("error.type = %q, want %q", doc.Error.Type, tc.wantErrorType)
				}
				if doc.Error.Code != tc.wantErrorCode {
					t.Errorf("error.code = %q, want %q", doc.Error.Code, tc.wantErrorCode)
				}
				if doc.Error.Message == "" {
					t.Error("error.message is empty")
				}
			}

			if tc.wantKeyAlias == "" {
				if doc.LLM.Key != nil && doc.LLM.Key.Alias != "" {
					t.Errorf("llm.key.alias = %q, want empty", doc.LLM.Key.Alias)
				}
			} else {
				if doc.LLM.Key == nil || doc.LLM.Key.Alias != tc.wantKeyAlias {
					t.Errorf("llm.key.alias = %v, want %q", doc.LLM.Key, tc.wantKeyAlias)
				}
			}
			// The key hash is present on every gateway record, including an
			// auth failure where it is the hash of what was attempted.
			if doc.LLM.Key == nil || doc.LLM.Key.Hash == "" {
				t.Error("llm.key.hash is absent; credential-spray clustering depends on it")
			}
		})
	}
}

// TestMapGateway_BudgetAndRateLimitShareAStatusButNotAnAction is the
// regression guard for the reason error.type exists. Both refusals are
// HTTP 429. A rule that grouped enforcement by status code would merge
// "this key is out of money" with "this key is going too fast" -- two
// different incidents with two different responses.
func TestMapGateway_BudgetAndRateLimitShareAStatusButNotAnAction(t *testing.T) {
	_, budget := mapGatewayFixture(t, "gateway_budget_block")
	_, rate := mapGatewayFixture(t, "gateway_rate_limited")

	bs, rs := *budget.HTTP.Response.StatusCode, *rate.HTTP.Response.StatusCode
	if bs != rs {
		t.Fatalf("fixtures no longer share a status code (%d vs %d); this test's premise is gone", bs, rs)
	}
	if budget.Error.Type == rate.Error.Type {
		t.Errorf("error.type is %q for both; the two refusals are indistinguishable", budget.Error.Type)
	}
	if budget.Event.Action == rate.Event.Action {
		t.Errorf("event.action is %q for both", budget.Event.Action)
	}
}

// TestMapGateway_NoContentFieldsEverEmitted guards the separation the two
// planes depend on. If a gateway document carried an empty llm.output,
// then "NOT llm.output: *" would silently also mean "or it is a gateway
// document", quietly corrupting the canary detection's negative case.
func TestMapGateway_NoContentFieldsEverEmitted(t *testing.T) {
	for _, name := range gatewayFixtures {
		t.Run(name, func(t *testing.T) {
			_, doc := mapGatewayFixture(t, name)
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			var generic map[string]json.RawMessage
			if err := json.Unmarshal(raw, &generic); err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				"user_prompt", "system_prompt", "output", "messages",
				"message_count", "output_length", "generation_count",
			} {
				if bytes.Contains(generic["llm"], []byte(`"`+forbidden+`"`)) {
					t.Errorf("gateway document carries llm.%s; the gateway never sees content: %s", forbidden, generic["llm"])
				}
			}
		})
	}
}

// TestMapGateway_AbsentNotZero applies the project's standing rule to the
// gateway mapper: a refused request reports spend 0.0 and 0 tokens on the
// wire, and none of it may reach the document.
func TestMapGateway_AbsentNotZero(t *testing.T) {
	for _, name := range []string{"gateway_budget_block", "gateway_auth_failure", "gateway_rate_limited"} {
		t.Run(name, func(t *testing.T) {
			_, doc := mapGatewayFixture(t, name)
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				`"usage"`, `"input_tokens"`, `"output_tokens"`, `"total_cost_usd"`,
			} {
				if bytes.Contains(raw, []byte(forbidden)) {
					t.Errorf("document contains %s for a request that never ran: %s", forbidden, raw)
				}
			}
			if doc.GenAI != nil && doc.GenAI.Response != nil {
				t.Errorf("gen_ai.response = %+v, want nil -- nothing responded", doc.GenAI.Response)
			}
		})
	}
}

// TestMapGateway_EventStartIsPopulated confirms the field cross-plane
// correlation actually compares. @timestamp is not it -- see
// docs/CORRELATION.md §5 -- so a gateway document without event.start is
// uncorrelatable regardless of how complete it otherwise looks.
func TestMapGateway_EventStartIsPopulated(t *testing.T) {
	for _, name := range gatewayFixtures {
		t.Run(name, func(t *testing.T) {
			_, doc := mapGatewayFixture(t, name)
			if doc.Event.Start == "" {
				t.Error("event.start is empty; this document cannot be correlated")
			}
			if doc.Event.End == "" {
				t.Error("event.end is empty")
			}
			if doc.Trace == nil || doc.Trace.ID == "" {
				t.Error("trace.id is absent; this document cannot be joined")
			}
		})
	}
}

// TestMapGateway_UnknownStatusEmitsNoCategorization confirms that a status
// value this mapper does not recognise produces no event.type at all,
// rather than defaulting to allowed or denied. "We could not tell" is not
// a categorization.
func TestMapGateway_UnknownStatusEmitsNoCategorization(t *testing.T) {
	ev := &model.LLMEvent{
		TraceID: "t1",
		Source:  model.SourceLiteLLM,
		Status:  model.StatusUnknown,
		Gateway: &model.GatewayDetail{RequestID: "r1"},
	}
	doc := MapGateway(ev, fixedGatewayCfg)
	if len(doc.Event.Type) != 0 {
		t.Errorf("event.type = %v, want empty for an unknown status", doc.Event.Type)
	}
	if doc.Event.Outcome != "" {
		t.Errorf("event.outcome = %q, want empty for an unknown status", doc.Event.Outcome)
	}
}

// TestMapGateway_RelatedUserCollectsBothIdentities confirms the pivot
// field carries who asked *and* which credential paid, without either
// overwriting the other's own field.
func TestMapGateway_RelatedUserCollectsBothIdentities(t *testing.T) {
	ev := &model.LLMEvent{
		TraceID: "t1",
		UserID:  "anwesh-lab",
		Source:  model.SourceLiteLLM,
		Status:  model.StatusSuccess,
		Gateway: &model.GatewayDetail{RequestID: "chatcmpl-1", KeyAlias: "alice", KeyHash: "h"},
	}
	doc := MapGateway(ev, fixedGatewayCfg)

	if doc.User == nil || doc.User.ID != "anwesh-lab" {
		t.Errorf("user.id = %v, want the end user", doc.User)
	}
	if doc.LLM.Key == nil || doc.LLM.Key.Alias != "alice" {
		t.Errorf("llm.key.alias = %v, want the credential", doc.LLM.Key)
	}
	if doc.Related == nil || !equalStrings(doc.Related.User, []string{"anwesh-lab", "alice"}) {
		t.Errorf("related.user = %v, want both identities", doc.Related)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestBothMappers_ShareCommonFieldConstruction is the property that makes
// a cross-plane query possible at all: for the same underlying facts, the
// fields both datasets carry must be built identically. If the two mappers
// ever formatted a timestamp differently, both would index fine and only
// diverge under a range query -- the least visible place for a bug.
func TestBothMappers_ShareCommonFieldConstruction(t *testing.T) {
	shared := model.LLMEvent{
		TraceID:          "shared-trace-1",
		SessionID:        "s1",
		UserID:           "u1",
		RequestTimestamp: mustTime(t, "2026-08-01T10:00:00.5Z"),
		StartTime:        mustTime(t, "2026-08-01T10:00:00Z"),
		EndTime:          mustTime(t, "2026-08-01T10:00:01Z"),
		Status:           model.StatusSuccess,
	}

	content := shared
	content.Source = model.SourceLangfuse
	gateway := shared
	gateway.Source = model.SourceLiteLLM
	gateway.Gateway = &model.GatewayDetail{RequestID: "chatcmpl-1"}

	cdoc := Map(&content, DefaultConfig(""))
	gdoc := MapGateway(&gateway, fixedGatewayCfg)

	for _, f := range []struct {
		name       string
		got, other string
	}{
		{"@timestamp", cdoc.Timestamp, gdoc.Timestamp},
		{"event.start", cdoc.Event.Start, gdoc.Event.Start},
		{"event.end", cdoc.Event.End, gdoc.Event.End},
		{"event.outcome", cdoc.Event.Outcome, gdoc.Event.Outcome},
		{"trace.id", cdoc.Trace.ID, gdoc.Trace.ID},
		{"ecs.version", cdoc.ECS.Version, gdoc.ECS.Version},
		{"event.kind", cdoc.Event.Kind, gdoc.Event.Kind},
		{"event.module", cdoc.Event.Module, gdoc.Event.Module},
	} {
		if f.got != f.other {
			t.Errorf("%s differs between planes for identical input: content=%q gateway=%q", f.name, f.got, f.other)
		}
		if f.got == "" {
			t.Errorf("%s is empty on both planes", f.name)
		}
	}

	// The one field that must NOT match, since it is what tells them apart.
	if cdoc.Event.Dataset == gdoc.Event.Dataset {
		t.Errorf("both planes report event.dataset %q; nothing distinguishes them", cdoc.Event.Dataset)
	}
	if cdoc.Event.Dataset != DatasetLangfuse || gdoc.Event.Dataset != DatasetLiteLLM {
		t.Errorf("datasets = %q / %q, want %q / %q", cdoc.Event.Dataset, gdoc.Event.Dataset, DatasetLangfuse, DatasetLiteLLM)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return v
}

// TestMapGateway_DatasetIsNotHardcodedToLangfuse is a direct regression
// guard on the third hardcoded constant recorded in notes.md. event.dataset
// was a literal "wiretap.langfuse" inside the mapper, which would have
// labelled every gateway document as a Langfuse document.
func TestMapGateway_DatasetIsNotHardcodedToLangfuse(t *testing.T) {
	for _, name := range gatewayFixtures {
		_, doc := mapGatewayFixture(t, name)
		if strings.Contains(doc.Event.Dataset, "langfuse") {
			t.Errorf("%s: event.dataset = %q on a gateway document", name, doc.Event.Dataset)
		}
	}
}
