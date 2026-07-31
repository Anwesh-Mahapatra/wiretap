package esink

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"wiretap/internal/ecs"
	"wiretap/internal/model"
)

// TestBootstrap_IdempotentSecondRunDoesNotError simulates the index
// existing on the second call (via HEAD returning 404 then 200) and
// confirms Bootstrap succeeds both times without attempting to re-create
// an existing index.
func TestBootstrap_IdempotentSecondRunDoesNotError(t *testing.T) {
	var templatePuts, indexExistsChecks, indexCreates int32
	indexCreated := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/_index_template/wiretap-llm-events-template":
			atomic.AddInt32(&templatePuts, 1)
			w.Write([]byte(`{"acknowledged":true}`))
		case r.Method == http.MethodHead && r.URL.Path == "/wiretap-llm-events-000001":
			atomic.AddInt32(&indexExistsChecks, 1)
			if indexCreated {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case r.Method == http.MethodPut && r.URL.Path == "/wiretap-llm-events-000001":
			atomic.AddInt32(&indexCreates, 1)
			indexCreated = true
			w.Write([]byte(`{"acknowledged":true,"shards_acknowledged":true,"index":"wiretap-llm-events-000001"}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	client := New(srv.URL)
	cfg := BootstrapConfig{IndexBase: "wiretap-llm-events"}

	if err := client.Bootstrap(context.Background(), cfg); err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}
	if err := client.Bootstrap(context.Background(), cfg); err != nil {
		t.Fatalf("second Bootstrap (must be idempotent): %v", err)
	}

	if got := atomic.LoadInt32(&templatePuts); got != 2 {
		t.Errorf("templatePuts = %d, want 2 (PUT is itself idempotent, called every run)", got)
	}
	if got := atomic.LoadInt32(&indexCreates); got != 1 {
		t.Errorf("indexCreates = %d, want 1 (second run must skip creation)", got)
	}
	if got := atomic.LoadInt32(&indexExistsChecks); got != 2 {
		t.Errorf("indexExistsChecks = %d, want 2", got)
	}
}

// flattenMapping walks a rendered mapping and returns every leaf field as
// a dotted path -> its full type definition. Walking the *rendered* output
// rather than comparing sharedProperties() to itself is the point: a
// future edit could override a shared field inside one dataset's own
// additions, and comparing the source of truth to itself would never
// notice.
func flattenMapping(m map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	var walk func(node map[string]any, prefix string)
	walk = func(node map[string]any, prefix string) {
		propsAny, ok := node["properties"]
		if !ok {
			return
		}
		props, ok := propsAny.(map[string]any)
		if !ok {
			return
		}
		for name, defAny := range props {
			def, ok := defAny.(map[string]any)
			if !ok {
				continue
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			if _, nested := def["properties"]; nested {
				walk(def, path)
				continue
			}
			out[path] = def
		}
	}
	walk(m, "")
	return out
}

func sameDefinition(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || fmt.Sprint(av) != fmt.Sprint(bv) {
			return false
		}
	}
	return true
}

// TestSharedFieldsHaveIdenticalMappings is the load-bearing guard on the
// two-index design, and it deserves its length.
//
// Both indices sit behind one shared pattern (esink.SharedIndexPattern) so
// a single Kibana data view and, critically, an EQL sequence query can
// span them. A field queried across that pattern must have the SAME type
// in both indices. If it does not, Elasticsearch does not error -- a
// cross-index query over a field mapped one way here and another way there
// returns wrong results, silently. That is the same failure class as the
// three bugs recorded in notes.md: no exception, no empty field, no
// document that looks odd, just an answer that is quietly false.
//
// sharedProperties() makes divergence structurally hard by defining the
// common fields once. This test makes it *detectable* anyway, because
// "structurally hard" is not "impossible": either mapping function could
// override a shared field in its own additions, and this is what would
// catch that.
func TestSharedFieldsHaveIdenticalMappings(t *testing.T) {
	content := flattenMapping(contentIndexMapping())
	gateway := flattenMapping(gatewayIndexMapping())

	shared := flattenMapping(map[string]any{"properties": sharedProperties()})
	if len(shared) == 0 {
		t.Fatal("sharedProperties() flattened to nothing -- the walk is broken, not the mapping")
	}

	// 1. Every shared field must appear in both rendered templates, with
	//    exactly the definition sharedProperties() gave it.
	for path, want := range shared {
		c, inContent := content[path]
		g, inGateway := gateway[path]
		if !inContent {
			t.Errorf("shared field %q is missing from the content mapping", path)
			continue
		}
		if !inGateway {
			t.Errorf("shared field %q is missing from the gateway mapping", path)
			continue
		}
		if !sameDefinition(c, want) {
			t.Errorf("shared field %q is %v in the content mapping but %v in sharedProperties -- a dataset overrode a shared field", path, c, want)
		}
		if !sameDefinition(g, want) {
			t.Errorf("shared field %q is %v in the gateway mapping but %v in sharedProperties -- a dataset overrode a shared field", path, g, want)
		}
	}

	// 2. Any field present in BOTH templates must be identically mapped,
	//    whether or not it came from sharedProperties. llm.total_cost_usd
	//    is the live example: both planes report cost, and it is declared
	//    in each mapping function separately.
	for path, c := range content {
		g, ok := gateway[path]
		if !ok {
			continue
		}
		if !sameDefinition(c, g) {
			t.Errorf("field %q is mapped %v in the content index and %v in the gateway index -- a cross-index query over %s returns wrong results, without erroring", path, c, g, SharedIndexPattern)
		}
	}
}

// TestBothMappingsAreFullyExplicit confirms neither template leaves
// anything to Elasticsearch's dynamic mapping. A dynamically-mapped field
// gets whatever type the first document happened to imply, which for a
// string is text+keyword rather than the wildcard the canary detection
// needs -- and the detection then silently returns nothing.
func TestBothMappingsAreFullyExplicit(t *testing.T) {
	for name, m := range map[string]map[string]any{
		"content": contentIndexMapping(),
		"gateway": gatewayIndexMapping(),
	} {
		t.Run(name, func(t *testing.T) {
			flat := flattenMapping(m)
			if len(flat) == 0 {
				t.Fatal("mapping flattened to nothing")
			}
			for path, def := range flat {
				if _, ok := def["type"]; !ok {
					t.Errorf("field %q has no explicit type: %v", path, def)
				}
			}
		})
	}
}

// TestGatewayMappingCarriesNoContentFields is the storage-layer half of
// internal/ecs's TestMapGateway_NoContentFieldsEverEmitted. Mapping a
// content field in the gateway index would be dead schema that invites
// someone to query llm.output across the shared pattern and quietly match
// gateway documents -- see notes.md's entry on the defect that lived
// between two individually correct decisions.
func TestGatewayMappingCarriesNoContentFields(t *testing.T) {
	flat := flattenMapping(gatewayIndexMapping())
	for _, forbidden := range []string{
		"llm.output", "llm.user_prompt", "llm.system_prompt", "llm.messages",
		"llm.message_count", "llm.output_length", "llm.generation_count",
		"llm.errored_generation_count",
	} {
		if _, ok := flat[forbidden]; ok {
			t.Errorf("gateway mapping declares %q; the gateway plane has no content", forbidden)
		}
	}
}

// TestEveryECSDocumentFieldIsMapped walks the actual ecs.Document struct
// via its JSON output and asserts each dataset's mapping declares every
// field that dataset's mapper can produce.
//
// This closes the gap the mapping tests above cannot: they check the two
// mappings against each other, not against what the code actually emits.
// A field added to internal/ecs and forgotten here would be dynamically
// mapped -- exactly what "no field left to dynamic mapping" is meant to
// prevent.
func TestEveryECSDocumentFieldIsMapped(t *testing.T) {
	for _, tc := range []struct {
		name    string
		doc     []byte
		mapping map[string]any
	}{
		{"content", contentSampleDoc(t), contentIndexMapping()},
		{"gateway", gatewaySampleDoc(t), gatewayIndexMapping()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flat := flattenMapping(tc.mapping)
			var generic map[string]any
			if err := json.Unmarshal(tc.doc, &generic); err != nil {
				t.Fatalf("unmarshaling sample document: %v", err)
			}
			for _, path := range documentLeafPaths(generic, "") {
				if _, ok := flat[path]; !ok {
					t.Errorf("document emits %q but the %s mapping does not declare it -- it would be dynamically mapped", path, tc.name)
				}
			}
		})
	}
}

// documentLeafPaths returns every dotted leaf path in a decoded document.
// Arrays are treated as leaves at their own path, matching how
// Elasticsearch maps them (a keyword field holds one value or many).
func documentLeafPaths(node map[string]any, prefix string) []string {
	var out []string
	for k, v := range node {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		if child, ok := v.(map[string]any); ok {
			out = append(out, documentLeafPaths(child, path)...)
			continue
		}
		out = append(out, path)
	}
	return out
}

// sampleEvent is an LLMEvent with every field a source could populate set,
// so the documents built from it exercise the widest shape each mapper can
// produce. Deliberately maximal: a field left unset here is a field
// TestEveryECSDocumentFieldIsMapped cannot check.
func sampleEvent() model.LLMEvent {
	tokens, cost, maxTok := 42, 0.0001, 256
	dur := 500 * time.Millisecond
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	return model.LLMEvent{
		TraceID:          "t1",
		SessionID:        "s1",
		UserID:           "u1",
		TraceName:        "wiretap-benign",
		RequestTimestamp: now,
		StartTime:        now,
		EndTime:          now.Add(dur),
		IngestTimestamp:  now.Add(time.Second),
		Duration:         &dur,
		RequestModel:     "llama-3.3-70b-versatile",
		MaxTokens:        &maxTok,
		Messages:         []model.Message{{Role: "system", Content: "sys"}, {Role: "user", Content: "hi"}},
		OutputContent:    "hello",
		OutputRole:       "assistant",
		ResponseID:       "chatcmpl-1",
		ResponseModel:    "groq/llama-3.3-70b-versatile",
		InputTokens:      &tokens,
		OutputTokens:     &tokens,
		TotalCost:        &cost,
		GenerationCount:  1,
		Status:           model.StatusFailure,
		StatusMessage:    "Budget has been exceeded!",
		Outcome:          model.OutcomeBenign,
		Tags:             []string{"wiretap", "benign"},
		SourceRef:        "/project/p/traces/t1",
	}
}

func contentSampleDoc(t *testing.T) []byte {
	t.Helper()
	ev := sampleEvent()
	ev.Source = model.SourceLangfuse
	ev.ErroredGenerationCount = 2
	b, err := json.Marshal(ecs.Map(&ev, ecs.DefaultConfig("https://langfuse.example")))
	if err != nil {
		t.Fatalf("marshaling content document: %v", err)
	}
	return b
}

func gatewaySampleDoc(t *testing.T) []byte {
	t.Helper()
	ev := sampleEvent()
	ev.Source = model.SourceLiteLLM
	status, retries := 429, 0
	ev.Gateway = &model.GatewayDetail{
		RequestID:        "chatcmpl-1",
		CallID:           "c1",
		KeyAlias:         "alice",
		KeyHash:          "h1",
		TeamID:           "team",
		HTTPStatusCode:   &status,
		ErrorClass:       "BudgetExceededError",
		ErrorCode:        "429",
		Provider:         "groq",
		AttemptedRetries: &retries,
		RequesterIP:      "172.18.0.1",
		CallType:         "acompletion",
	}
	b, err := json.Marshal(ecs.MapGateway(&ev, ecs.DefaultGatewayConfig()))
	if err != nil {
		t.Fatalf("marshaling gateway document: %v", err)
	}
	return b
}
