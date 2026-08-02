package ecs

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wiretap/internal/model"
	"wiretap/internal/parse"
)

var update = flag.Bool("update", false, "update golden files in testdata/golden")

// fixedCfg makes Map's output deterministic across runs -- required for
// byte-comparable golden files.
var fixedCfg = DefaultConfig("https://langfuse.example.local")

const canary = "XK9-Canaries-77"

func loadRaw(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "raw", name+".json"))
	if err != nil {
		t.Fatalf("reading raw fixture %q: %v", name, err)
	}
	return data
}

func mapFixture(t *testing.T, name string) (*model.LLMEvent, *Document) {
	t.Helper()
	ev, err := parse.ParseLine(loadRaw(t, name), 1)
	if err != nil {
		t.Fatalf("parsing fixture %q: %v", name, err)
	}
	return ev, Map(ev, fixedCfg)
}

var scenarioNames = []string{"benign", "injection", "truncated"}

func TestMap_GoldenFiles(t *testing.T) {
	for _, name := range scenarioNames {
		t.Run(name, func(t *testing.T) {
			_, doc := mapFixture(t, name)

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
				t.Errorf("Map(%s) does not match golden file %s.\n--- got ---\n%s\n--- want ---\n%s", name, goldenPath, got, want)
			}
		})
	}
}

// TestMap_DurationIsIntegerNanoseconds guards the exact conversion
// event.duration depends on: Langfuse's real observed latency for the
// truncated scenario, 0.295 seconds, must become the integer 295000000
// (nanoseconds), never the float 0.295 and never silently truncated to 0.
func TestMap_DurationIsIntegerNanoseconds(t *testing.T) {
	_, doc := mapFixture(t, "truncated")

	if doc.Event.Duration == nil {
		t.Fatal("Event.Duration is nil")
	}
	if got, want := *doc.Event.Duration, int64(295_000_000); got != want {
		t.Errorf("Event.Duration = %d, want %d", got, want)
	}

	// Also confirm it round-trips through JSON as a bare integer, not a
	// float or a string -- the failure mode this test exists to catch.
	raw, err := json.Marshal(doc.Event)
	if err != nil {
		t.Fatalf("marshaling event: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"duration":295000000`)) {
		t.Errorf("event JSON does not contain the expected integer duration: %s", raw)
	}
	if bytes.Contains(raw, []byte("0.295")) {
		t.Errorf("event JSON leaked the raw float seconds value instead of converting it: %s", raw)
	}
}

// TestMap_InjectionOutputIsNotTheBenignVPNAnswer is a regression guard for
// the trace-merge bug (see notes.md): a Langfuse trace that fell back to
// session_id as its ID could pair one request's input with a *different*
// request's output. If that ever recurs, the injection scenario's mapped
// document would show the benign scenario's VPN troubleshooting answer
// instead of a refusal -- this test fails loudly and specifically if that
// happens, rather than as a generic content mismatch.
func TestMap_InjectionOutputIsNotTheBenignVPNAnswer(t *testing.T) {
	_, doc := mapFixture(t, "injection")

	if strings.Contains(doc.LLM.Output, "VPN") {
		t.Fatalf("injection trace's llm.output contains the BENIGN scenario's VPN answer -- this is exactly the trace-merge bug (see notes.md): %q", doc.LLM.Output)
	}
	if !strings.Contains(strings.ToLower(doc.LLM.Output), "can't") && !strings.Contains(strings.ToLower(doc.LLM.Output), "cannot") && !strings.Contains(strings.ToLower(doc.LLM.Output), "sorry") {
		t.Errorf("injection trace's llm.output does not look like a refusal: %q", doc.LLM.Output)
	}
}

// TestMap_CanaryOnlyInSystemPromptNeverInOutput guards the tripwire's own
// placement: the canary lives in the system prompt (an attempt to exfiltrate
// it would show up in the *output*), so if it ever leaked into llm.output
// on every fixture, a detection scoped to output would never distinguish a
// real exfiltration from background noise -- and a detection scoped to
// input would fire on every single request, forever, since the canary is
// present in literally every system prompt this project sends.
func TestMap_CanaryOnlyInSystemPromptNeverInOutput(t *testing.T) {
	for _, name := range scenarioNames {
		t.Run(name, func(t *testing.T) {
			_, doc := mapFixture(t, name)

			if !strings.Contains(doc.LLM.SystemPrompt, canary) {
				t.Errorf("llm.system_prompt does not contain the canary %q: %q", canary, doc.LLM.SystemPrompt)
			}
			if strings.Contains(doc.LLM.Output, canary) {
				t.Errorf("llm.output contains the canary %q -- a real exfiltration and background noise would be indistinguishable: %q", canary, doc.LLM.Output)
			}
		})
	}
}

// TestMap_NoGenAIFieldEmittedAsZeroSubstituteForMissing constructs an event
// with none of the observation-detail-only fields set (the common case for
// this pipeline today -- see internal/parse's package doc) and asserts the
// resulting JSON has no gen_ai.request.max_tokens, gen_ai.response.*, or
// gen_ai.usage.* keys at all, rather than those keys present with 0/""
// values standing in for "we don't know."
func TestMap_NoGenAIFieldEmittedAsZeroSubstituteForMissing(t *testing.T) {
	ev := &model.LLMEvent{
		TraceID: "t1",
		Source:  model.SourceLangfuse,
		// RequestModel, MaxTokens, ResponseModel, ResponseID,
		// FinishReasons, InputTokens, OutputTokens all left zero-valued.
	}

	doc := Map(ev, fixedCfg)

	if doc.GenAI == nil {
		t.Fatal("GenAI is nil, want non-nil (System/Operation are always known for this deployment)")
	}
	if doc.GenAI.Request != nil {
		t.Errorf("GenAI.Request = %+v, want nil (no request data was available)", doc.GenAI.Request)
	}
	if doc.GenAI.Response != nil {
		t.Errorf("GenAI.Response = %+v, want nil (no response data was available)", doc.GenAI.Response)
	}
	if doc.GenAI.Usage != nil {
		t.Errorf("GenAI.Usage = %+v, want nil (no usage data was available)", doc.GenAI.Usage)
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshaling document: %v", err)
	}
	for _, forbidden := range []string{
		`"max_tokens"`, `"input_tokens"`, `"output_tokens"`,
		`"finish_reasons"`, `"request"`, `"response"`, `"usage"`,
	} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Errorf("document JSON contains %s, which should be entirely absent, not zero-valued: %s", forbidden, raw)
		}
	}
	// System/Operation, by contrast, ARE always present -- the guarantee is
	// presence, not a particular value. With no provider evidence on the
	// event, System is the fallback marker (DefaultGenAISystem), which is
	// precisely not a plausible provider.
	if !bytes.Contains(raw, []byte(`"system":"`+DefaultGenAISystem+`"`)) {
		t.Errorf("document JSON is missing gen_ai.system: %s", raw)
	}
}

// TestMap_LabelsQuarantineOutcome confirms wiretap's ground-truth outcome
// label lands only under labels.*, never under a field a detection rule
// would naturally query (llm.*, gen_ai.*, tags).
func TestMap_LabelsQuarantineOutcome(t *testing.T) {
	_, doc := mapFixture(t, "injection")

	if doc.Labels.WiretapOutcome != "injection" {
		t.Errorf("Labels.WiretapOutcome = %q, want %q", doc.Labels.WiretapOutcome, "injection")
	}
	if doc.Labels.WiretapScenario != "wiretap-injection" {
		t.Errorf("Labels.WiretapScenario = %q", doc.Labels.WiretapScenario)
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshaling document: %v", err)
	}
	// "injection" must appear exactly where labels.wiretap_outcome put it,
	// and nowhere inside the llm.* or gen_ai.* objects.
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshaling document: %v", err)
	}
	if bytes.Contains(generic["llm"], []byte("injection")) {
		t.Errorf("llm.* contains the outcome label %q, which must be quarantined under labels.*: %s", "injection", generic["llm"])
	}
	if genAI, ok := generic["gen_ai"]; ok && bytes.Contains(genAI, []byte("injection")) {
		t.Errorf("gen_ai.* contains the outcome label %q, which must be quarantined under labels.*: %s", "injection", genAI)
	}
}

// TestMap_CostZeroVsAbsent guards llm.total_cost_usd's zero-vs-absent
// distinction the same way the gen_ai.* fields are guarded: a nil
// TotalCost (Langfuse reported totalCost: null) must produce no
// total_cost_usd key at all, while a real, reported 0.0 must produce
// "total_cost_usd":0, not be conflated with "unknown."
func TestMap_CostZeroVsAbsent(t *testing.T) {
	absent := &model.LLMEvent{TraceID: "t1", Source: model.SourceLangfuse, TotalCost: nil}
	docAbsent := Map(absent, fixedCfg)
	if docAbsent.LLM.TotalCostUSD != nil {
		t.Errorf("TotalCostUSD = %v, want nil for an unreported cost", docAbsent.LLM.TotalCostUSD)
	}
	rawAbsent, _ := json.Marshal(docAbsent)
	if bytes.Contains(rawAbsent, []byte("total_cost_usd")) {
		t.Errorf("document JSON contains total_cost_usd for a nil TotalCost: %s", rawAbsent)
	}

	zero := 0.0
	present := &model.LLMEvent{TraceID: "t2", Source: model.SourceLangfuse, TotalCost: &zero}
	docPresent := Map(present, fixedCfg)
	if docPresent.LLM.TotalCostUSD == nil || *docPresent.LLM.TotalCostUSD != 0 {
		t.Errorf("TotalCostUSD = %v, want a real, present 0", docPresent.LLM.TotalCostUSD)
	}
	rawPresent, _ := json.Marshal(docPresent)
	if !bytes.Contains(rawPresent, []byte(`"total_cost_usd":0`)) {
		t.Errorf("document JSON does not contain a present total_cost_usd:0: %s", rawPresent)
	}
}

// TestMap_EventIngestedComesFromEventNotClock confirms event.ingested is
// sourced from ev.IngestTimestamp (Langfuse's own createdAt, set by
// internal/parse) rather than from any clock Map might read -- Map has no
// clock to read in the first place, which is what makes it pure.
func TestMap_EventIngestedComesFromEventNotClock(t *testing.T) {
	when := time.Date(2026, 7, 28, 13, 53, 50, 623_000_000, time.UTC)
	ev := &model.LLMEvent{TraceID: "t1", Source: model.SourceLangfuse, IngestTimestamp: when}
	doc := Map(ev, fixedCfg)
	if doc.Event.Ingested != when.Format(time.RFC3339Nano) {
		t.Errorf("Event.Ingested = %q, want %q", doc.Event.Ingested, when.Format(time.RFC3339Nano))
	}

	// A zero IngestTimestamp (source never reported one) must omit
	// event.ingested entirely, not serialize as the zero time.
	noIngest := &model.LLMEvent{TraceID: "t2", Source: model.SourceLangfuse}
	docNoIngest := Map(noIngest, fixedCfg)
	if docNoIngest.Event.Ingested != "" {
		t.Errorf("Event.Ingested = %q, want empty for a zero IngestTimestamp", docNoIngest.Event.Ingested)
	}
	raw, _ := json.Marshal(docNoIngest)
	if bytes.Contains(raw, []byte("ingested")) {
		t.Errorf("document JSON contains event.ingested for a zero IngestTimestamp: %s", raw)
	}
}

// TestBuildReference tests buildReference's URL construction (joining
// ev.SourceRef onto cfg.LangfuseBaseURL for event.reference, the
// click-from-Kibana link back to Langfuse's UI) -- it has nothing to do
// with gen_ai.* schema validation despite the name-adjacent proximity to
// this file's other tests. See TestGenAIFieldsExistInReferenceDoc
// (genai_test.go) for the actual reference-document check.
func TestBuildReference(t *testing.T) {
	cases := []struct {
		name, base, ref, want string
	}{
		{"absolute ref ignores base", "https://base.example", "https://elsewhere.example/x", "https://elsewhere.example/x"},
		{"relative ref joins base", "https://base.example", "/project/p/traces/t", "https://base.example/project/p/traces/t"},
		{"relative ref joins base with trailing slash", "https://base.example/", "/project/p/traces/t", "https://base.example/project/p/traces/t"},
		{"no base falls back to bare path", "", "/project/p/traces/t", "/project/p/traces/t"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := buildReference(c.base, c.ref); got != c.want {
				t.Errorf("buildReference(%q, %q) = %q, want %q", c.base, c.ref, got, c.want)
			}
		})
	}
}

// TestMap_BlockedRequestIsNotAFreeSuccess is the mapper-side half of the
// blocked-request regression (see internal/parse's
// TestParseLine_BlockedRequest_UsageAndCostAbsentNotZero). The fixture is a
// real archived Langfuse response for a request LiteLLM refused on budget.
//
// The failure this guards against is not a crash or an empty document: it
// is a fully-populated, entirely plausible document that says a request
// succeeded, used zero tokens, and cost zero dollars -- which is what a
// free, successful request also looks like. Every assertion below is about
// telling those two apart.
func TestMap_BlockedRequestIsNotAFreeSuccess(t *testing.T) {
	_, doc := mapFixture(t, "blocked")

	if doc.Event.Outcome != "failure" {
		t.Errorf("event.outcome = %q, want %q", doc.Event.Outcome, "failure")
	}
	if doc.Error == nil || !strings.Contains(doc.Error.Message, "Budget has been exceeded") {
		t.Errorf("error.message = %v, want LiteLLM's enforcement text", doc.Error)
	}
	if doc.LLM.ErroredGenerationCount == 0 {
		t.Error("llm.errored_generation_count = 0, want > 0")
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshaling document: %v", err)
	}
	// The zeros Langfuse reported must not appear anywhere as measurements.
	for _, forbidden := range []string{
		`"usage"`, `"input_tokens"`, `"output_tokens"`, `"total_cost_usd"`,
	} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Errorf("document JSON contains %s for a request that never ran -- absent, not zero: %s", forbidden, raw)
		}
	}
	// No model answered, so no answering model may be claimed.
	if doc.GenAI != nil && doc.GenAI.Response != nil {
		t.Errorf("gen_ai.response = %+v, want nil -- nothing responded", doc.GenAI.Response)
	}
	// The requested model IS known and should still be reported.
	if doc.GenAI == nil || doc.GenAI.Request == nil || doc.GenAI.Request.Model == "" {
		t.Error("gen_ai.request.model is absent, want the model the caller asked for")
	}
}

// TestMap_SuccessfulRequestCarriesNoErrorObject confirms the error.* object
// is genuinely absent on a normal request, so a detection querying for the
// existence of error.message doesn't match every document ever indexed.
func TestMap_SuccessfulRequestCarriesNoErrorObject(t *testing.T) {
	_, doc := mapFixture(t, "benign")
	if doc.Error != nil {
		t.Errorf("Error = %+v, want nil on a successful request", doc.Error)
	}
	raw, _ := json.Marshal(doc)
	if bytes.Contains(raw, []byte(`"error"`)) {
		t.Errorf("document JSON contains an error object on a successful request: %s", raw)
	}
}
