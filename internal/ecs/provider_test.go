package ecs

import (
	"encoding/json"
	"strings"
	"testing"

	"wiretap/internal/model"
)

// TestDeriveGenAISystem is the fix for the first hardcoded constant
// recorded in notes.md. gen_ai.system was the literal "groq" on every
// document this project ever indexed -- correct only while config.yaml had
// exactly one model_list entry, and a confident lie the day it had two.
//
// The cases below are ordered to make the failure mode visible: a
// non-Groq model must produce a non-Groq provider, and the naive
// implementation (strings.Cut on "/") must be shown to be insufficient
// rather than merely unfashionable.
func TestDeriveGenAISystem(t *testing.T) {
	for _, tc := range []struct {
		name string

		gatewayProvider string
		responseModel   string
		requestModel    string

		want   string
		wantOK bool
	}{
		{
			name:            "gateway provider is preferred over everything",
			gatewayProvider: "groq",
			responseModel:   "openai/gpt-4o", // deliberately contradictory
			want:            "groq",
			wantOK:          true,
		},
		{
			name:          "derived from the served model's route prefix",
			responseModel: "groq/llama-3.3-70b-versatile",
			want:          "groq",
			wantOK:        true,
		},
		{
			// The case the whole fix exists for.
			name:          "a non-Groq model does not report groq",
			responseModel: "openai/gpt-4o",
			want:          "openai",
			wantOK:        true,
		},
		{
			name:          "anthropic",
			responseModel: "anthropic/claude-sonnet-4-5",
			want:          "anthropic",
			wantOK:        true,
		},
		{
			name:         "falls back to the requested model when nothing served it",
			requestModel: "openai/gpt-4o",
			want:         "openai",
			wantOK:       true,
		},
		{
			// An unprefixed model is what this deployment's content plane
			// carries on a *refused* request, and what its synthetic
			// fixtures carry throughout. Falling back is correct; claiming
			// to have derived it is not.
			name:          "unprefixed model falls back",
			responseModel: "llama-3.3-70b-versatile",
			want:          DefaultGenAISystem,
			wantOK:        false,
		},
		{
			name:   "nothing at all falls back",
			want:   DefaultGenAISystem,
			wantOK: false,
		},
		{
			// An unrecognised prefix is NOT passed through. Emitting it raw
			// would put an unvalidated string into a field whose entire
			// value is that its vocabulary is known.
			name:          "unknown prefix is not passed through",
			responseModel: "some-new-provider/some-model",
			want:          DefaultGenAISystem,
			wantOK:        false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := deriveGenAISystem(tc.gatewayProvider, tc.responseModel, tc.requestModel, DefaultGenAISystem)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("deriveGenAISystem(%q, %q, %q) = (%q, %v), want (%q, %v)",
					tc.gatewayProvider, tc.responseModel, tc.requestModel, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestDeriveGenAISystem_PrefixIsNotTheSpecValue is the reason
// litellmProviderToGenAISystem is a table rather than a strings.Cut.
//
// For a majority of providers LiteLLM's route prefix and the
// OpenTelemetry gen_ai.system value are simply different strings. A naive
// split would emit "bedrock" where the spec says "aws.bedrock" -- a
// plausible-looking value that is not in the vocabulary at all, and which
// would look perfectly fine in this deployment because "groq" happens to
// be one of the few that round-trip unchanged.
func TestDeriveGenAISystem_PrefixIsNotTheSpecValue(t *testing.T) {
	for _, tc := range []struct{ model, naive, want string }{
		{"bedrock/anthropic.claude-v2", "bedrock", "aws.bedrock"},
		{"azure/gpt-4o", "azure", "azure.ai.openai"},
		{"azure_ai/mistral-large", "azure_ai", "azure.ai.inference"},
		{"vertex_ai/gemini-1.5-pro", "vertex_ai", "gcp.vertex_ai"},
		{"gemini/gemini-1.5-flash", "gemini", "gcp.gemini"},
		{"mistral/mistral-large-latest", "mistral", "mistral_ai"},
		{"watsonx/granite-13b", "watsonx", "ibm.watsonx.ai"},
	} {
		t.Run(tc.model, func(t *testing.T) {
			got, ok := deriveGenAISystem("", tc.model, "", DefaultGenAISystem)
			if !ok {
				t.Fatalf("deriveGenAISystem(%q) did not recognise the provider", tc.model)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if got == tc.naive {
				t.Errorf("got %q, which is what a naive strings.Cut would produce -- and is not the spec value %q", got, tc.want)
			}
		})
	}
}

// TestMap_NonGroqModelDoesNotClaimGroq is the end-to-end version, on the
// content plane, through the real mapper.
func TestMap_NonGroqModelDoesNotClaimGroq(t *testing.T) {
	ev := &model.LLMEvent{
		TraceID:       "t1",
		Source:        model.SourceLangfuse,
		Status:        model.StatusSuccess,
		ResponseModel: "openai/gpt-4o",
		RequestModel:  "gpt-4o",
	}
	doc := Map(ev, DefaultConfig(""))

	if doc.GenAI == nil {
		t.Fatal("gen_ai is nil")
	}
	if doc.GenAI.System != "openai" {
		t.Errorf("gen_ai.system = %q, want %q", doc.GenAI.System, "openai")
	}
	raw, _ := json.Marshal(doc)
	if strings.Contains(string(raw), `"system":"groq"`) {
		t.Errorf("document claims groq for an OpenAI-served request: %s", raw)
	}
}

// TestMapGateway_UsesGatewayReportedProvider confirms the gateway plane
// uses LiteLLM's own custom_llm_provider rather than inferring from a
// string -- the proxy stating what it routed to beats parsing a model
// name, and is available on every successful gateway record.
func TestMapGateway_UsesGatewayReportedProvider(t *testing.T) {
	ev := &model.LLMEvent{
		TraceID:       "t1",
		Source:        model.SourceLiteLLM,
		Status:        model.StatusSuccess,
		ResponseModel: "bedrock/anthropic.claude-v2",
		Gateway:       &model.GatewayDetail{RequestID: "chatcmpl-1", Provider: "bedrock"},
	}
	doc := MapGateway(ev, DefaultGatewayConfig())
	if doc.GenAI.System != "aws.bedrock" {
		t.Errorf("gen_ai.system = %q, want %q", doc.GenAI.System, "aws.bedrock")
	}
}

// TestMap_ExistingGroqDocumentsUnchanged is the other half of the fix:
// the derivation must not disturb documents that were already right.
// Every real Langfuse success in this project carries a "groq/"-prefixed
// model, and every synthetic fixture carries an unprefixed one -- the
// first derives to groq, the second falls back to groq. Both paths, same
// answer, no golden file moved.
func TestMap_ExistingGroqDocumentsUnchanged(t *testing.T) {
	for _, tc := range []struct{ name, responseModel string }{
		{"real captured data (prefixed)", "groq/llama-3.3-70b-versatile"},
		{"synthetic fixture (unprefixed)", "llama-3.3-70b-versatile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := &model.LLMEvent{
				TraceID:       "t1",
				Source:        model.SourceLangfuse,
				Status:        model.StatusSuccess,
				ResponseModel: tc.responseModel,
			}
			doc := Map(ev, DefaultConfig(""))
			if doc.GenAI.System != "groq" {
				t.Errorf("gen_ai.system = %q, want groq", doc.GenAI.System)
			}
		})
	}
}

// TestDeriveOperation covers gen_ai.operation.name's assessment. Unlike
// gen_ai.system, a constant is defensible on the content plane -- Langfuse
// types every call as a GENERATION and records no distinction to derive
// from. The gateway plane does have call_type, so it derives.
func TestDeriveOperation(t *testing.T) {
	for _, tc := range []struct{ callType, want string }{
		{"acompletion", "chat"},
		{"completion", "chat"},
		{"aembedding", "embeddings"},
		{"embedding", "embeddings"},
		{"atext_completion", "text_completion"},
		// A refused request never got a call_type; the caller was still
		// attempting a chat completion.
		{"", DefaultGenAIOperation},
		// An unrecognised call type falls back rather than passing through
		// a value that is not in gen_ai.operation.name's vocabulary.
		{"aresponses", DefaultGenAIOperation},
	} {
		t.Run(tc.callType, func(t *testing.T) {
			if got := deriveOperation(tc.callType, DefaultGenAIOperation); got != tc.want {
				t.Errorf("deriveOperation(%q) = %q, want %q", tc.callType, got, tc.want)
			}
		})
	}
}

// TestMapGateway_EmbeddingsCallReportsEmbeddings is the end-to-end proof
// that operation is derived on the gateway plane rather than asserted.
func TestMapGateway_EmbeddingsCallReportsEmbeddings(t *testing.T) {
	ev := &model.LLMEvent{
		TraceID: "t1",
		Source:  model.SourceLiteLLM,
		Status:  model.StatusSuccess,
		Gateway: &model.GatewayDetail{RequestID: "emb-1", CallType: "aembedding"},
	}
	doc := MapGateway(ev, DefaultGatewayConfig())
	if doc.GenAI.Operation == nil || doc.GenAI.Operation.Name != "embeddings" {
		t.Errorf("gen_ai.operation.name = %v, want embeddings", doc.GenAI.Operation)
	}
}

// TestGenAISystemValuesAreInTheOTelVocabulary checks every value this
// mapper can emit against the OpenTelemetry Gen AI attributes registry --
// the spec docs/reference/ecs-gen_ai.md itself points at for
// gen_ai.system. Transcribed from that registry on 2026-08-01.
//
// The reference doc in this repo covers gen_ai.* field *names* and types;
// it does not enumerate gen_ai.system's allowed *values*, so this list is
// the equivalent guard for the value vocabulary. Without it, a typo in the
// mapping table would produce a field that passes every existing test and
// is silently outside the schema.
func TestGenAISystemValuesAreInTheOTelVocabulary(t *testing.T) {
	otelWellKnown := map[string]bool{
		"anthropic": true, "aws.bedrock": true, "azure.ai.inference": true,
		"azure.ai.openai": true, "cohere": true, "deepseek": true,
		"gcp.gemini": true, "gcp.gen_ai": true, "gcp.vertex_ai": true,
		"groq": true, "ibm.watsonx.ai": true, "mistral_ai": true,
		"openai": true, "perplexity": true, "xai": true,
	}

	for prefix, system := range litellmProviderToGenAISystem {
		if !otelWellKnown[system] {
			t.Errorf("litellmProviderToGenAISystem[%q] = %q, which is not a well-known gen_ai.system value -- do not invent provider identifiers", prefix, system)
		}
	}
	if !otelWellKnown[DefaultGenAISystem] {
		t.Errorf("DefaultGenAISystem = %q, not a well-known value", DefaultGenAISystem)
	}
}

// TestGenAIOperationValuesAreInTheOTelVocabulary does the same for
// gen_ai.operation.name.
func TestGenAIOperationValuesAreInTheOTelVocabulary(t *testing.T) {
	otelWellKnown := map[string]bool{
		"chat": true, "create_agent": true, "embeddings": true,
		"execute_tool": true, "generate_content": true, "invoke_agent": true,
		"invoke_workflow": true, "retrieval": true, "text_completion": true,
	}
	for callType, op := range callTypeToOperation {
		if !otelWellKnown[op] {
			t.Errorf("callTypeToOperation[%q] = %q, which is not a well-known gen_ai.operation.name value", callType, op)
		}
	}
	if !otelWellKnown[DefaultGenAIOperation] {
		t.Errorf("DefaultGenAIOperation = %q, not a well-known value", DefaultGenAIOperation)
	}
}
