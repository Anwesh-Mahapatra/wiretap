package ecs

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"wiretap/internal/model"
)

// TestDeriveGenAISystem is the fix for the first hardcoded constant
// recorded in notes.md. gen_ai.system was the literal "groq" on every
// document this project ever indexed -- correct only while config.yaml had
// exactly one model_list entry, and a confident lie the day it had two.
// The derivation then repeated the same failure one level up: a missing
// table entry ("ollama_chat") resolved to the same "groq" fallback, so the
// fix's second half is that an unrecognised provider now yields ("",
// false) and the caller decides, visibly, what that means.
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
			// The real captured Ollama spend row, verbatim -- the request
			// whose six documents were labelled "groq" in both indices
			// (LiteLLM request chatcmpl-21c9cc3c-1914-4e18-8c4f-97d9ed188bc6,
			// trace.id injection-e27712c81441ab667ac2b8311c163e3d). Every
			// earlier fixture in this file used an invented prefix, which is
			// exactly how a real one got through.
			name:            "ollama_chat via the gateway's own provider field",
			gatewayProvider: "ollama_chat",
			responseModel:   "ollama_chat/llama3.1:8b",
			requestModel:    "local-llama",
			want:            "ollama",
			wantOK:          true,
		},
		{
			// Same real request, content-plane view: no gateway provider,
			// only the prefixed served model and the unprefixed alias.
			name:          "ollama_chat derived from the served model prefix",
			responseModel: "ollama_chat/llama3.1:8b",
			requestModel:  "local-llama",
			want:          "ollama",
			wantOK:        true,
		},
		{
			name:         "falls back to the requested model when nothing served it",
			requestModel: "openai/gpt-4o",
			want:         "openai",
			wantOK:       true,
		},
		{
			// An unprefixed model is what this deployment's planes carry on
			// a *refused* request (verified against the real budget-block
			// spend rows in the archive: custom_llm_provider is ""). Nothing
			// identified a provider, so ok is false and system empty -- the
			// caller decides what an unidentified provider means.
			name:          "unprefixed model is not identified",
			responseModel: "llama-3.3-70b-versatile",
			want:          "",
			wantOK:        false,
		},
		{
			name:   "nothing at all is not identified",
			want:   "",
			wantOK: false,
		},
		{
			// An unrecognised prefix is NOT passed through. Emitting it raw
			// would put an unvalidated string into a field whose entire
			// value is that its vocabulary is known.
			name:          "unknown prefix is not passed through",
			responseModel: "some-new-provider/some-model",
			want:          "",
			wantOK:        false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := deriveGenAISystem(tc.gatewayProvider, tc.responseModel, tc.requestModel)
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
			got, ok := deriveGenAISystem("", tc.model, "")
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
// model (verified against the live index and the captured fixtures), so
// every real Groq document derives to groq exactly as before. The proof
// for *deployed* documents is the archive reindex, not this test.
func TestMap_ExistingGroqDocumentsUnchanged(t *testing.T) {
	ev := &model.LLMEvent{
		TraceID:       "t1",
		Source:        model.SourceLangfuse,
		Status:        model.StatusSuccess,
		ResponseModel: "groq/llama-3.3-70b-versatile",
	}
	doc := Map(ev, DefaultConfig(""))
	if doc.GenAI.System != "groq" {
		t.Errorf("gen_ai.system = %q, want groq", doc.GenAI.System)
	}
}

// TestMap_UnidentifiedProviderIsVisiblyUnknown replaces the old synthetic
// unprefixed case, which expected "groq" only because the fallback
// happened to be "groq" -- the exact mechanism that mislabelled real
// Ollama documents. An event with no provider evidence now gets the
// marker: present on the document, never a plausible provider, and
// grep-able as a coverage audit.
func TestMap_UnidentifiedProviderIsVisiblyUnknown(t *testing.T) {
	ev := &model.LLMEvent{
		TraceID:       "t1",
		Source:        model.SourceLangfuse,
		Status:        model.StatusSuccess,
		ResponseModel: "llama-3.3-70b-versatile", // no route prefix
	}
	doc := Map(ev, DefaultConfig(""))
	if doc.GenAI.System != DefaultGenAISystem {
		t.Errorf("gen_ai.system = %q, want the %q marker", doc.GenAI.System, DefaultGenAISystem)
	}
	raw, _ := json.Marshal(doc)
	if strings.Contains(string(raw), `"system":"groq"`) {
		t.Errorf("unidentified provider claims groq -- the fallback is plausible again: %s", raw)
	}
}

// TestMapGateway_OllamaSpendRowReportsOllama is the end-to-end gateway
// case built from the real captured spend row (LiteLLM request
// chatcmpl-21c9cc3c-1914-4e18-8c4f-97d9ed188bc6): custom_llm_provider
// "ollama_chat", served model "ollama_chat/llama3.1:8b", requested alias
// "local-llama". This document was indexed with gen_ai.system "groq"
// before the fix.
func TestMapGateway_OllamaSpendRowReportsOllama(t *testing.T) {
	ev := &model.LLMEvent{
		TraceID:       "injection-e27712c81441ab667ac2b8311c163e3d",
		Source:        model.SourceLiteLLM,
		Status:        model.StatusSuccess,
		RequestModel:  "local-llama",
		ResponseModel: "ollama_chat/llama3.1:8b",
		Gateway:       &model.GatewayDetail{RequestID: "chatcmpl-21c9cc3c-1914-4e18-8c4f-97d9ed188bc6", Provider: "ollama_chat"},
	}
	doc := MapGateway(ev, DefaultGatewayConfig())
	if doc.GenAI.System != "ollama" {
		t.Errorf("gen_ai.system = %q, want %q", doc.GenAI.System, "ollama")
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
// The registry's actual rule: a well-known value MUST be used where one
// applies; otherwise a custom value MAY be used. This test used to forbid
// anything outside the well-known list -- stricter than the spec, which
// reads as authoritative while blocking the spec-sanctioned fix for a
// provider the spec has never heard of (Ollama). Values are therefore
// checked against the well-known list OR an explicit custom set whose
// every entry must carry its justification.
//
// The reference doc in this repo covers gen_ai.* field *names* and types;
// it does not enumerate gen_ai.system's allowed *values*, so this list is
// the equivalent guard for the value vocabulary.
func TestGenAISystemValuesAreInTheOTelVocabulary(t *testing.T) {
	otelWellKnown := map[string]bool{
		"anthropic": true, "aws.bedrock": true, "azure.ai.inference": true,
		"azure.ai.openai": true, "cohere": true, "deepseek": true,
		"gcp.gemini": true, "gcp.gen_ai": true, "gcp.vertex_ai": true,
		"groq": true, "ibm.watsonx.ai": true, "mistral_ai": true,
		"openai": true, "perplexity": true, "xai": true,
	}

	// customValues are spec-legal precisely because no well-known value
	// applies to these providers. Every entry must state why it exists --
	// an unjustified custom value is an invented identifier, which is what
	// this test exists to prevent.
	customValues := map[string]string{
		"ollama":      "Ollama has no well-known value; ollama and ollama_chat are the same product via different endpoints",
		"vllm":        "vLLM has no well-known value; hosted_vllm is a remote vLLM server, same product",
		"lm_studio":   "LM Studio has no well-known value",
		"llamafile":   "llamafile has no well-known value",
		"openrouter":  "OpenRouter has no well-known value; it is the system the instrumentation talked to",
		"together_ai": "Together AI has no well-known value",
	}

	for prefix, system := range litellmProviderToGenAISystem {
		if otelWellKnown[system] {
			continue
		}
		why, custom := customValues[system]
		if !custom {
			t.Errorf("litellmProviderToGenAISystem[%q] = %q, which is neither a well-known gen_ai.system value nor a justified custom one -- do not invent provider identifiers", prefix, system)
		} else if why == "" {
			t.Errorf("custom gen_ai.system value %q (from %q) has no recorded justification", system, prefix)
		}
	}

	// The fallback must NOT be a well-known provider value: its whole
	// purpose is that it can never be mistaken for an identified provider.
	// (This check used to assert the opposite, when the fallback was
	// "groq" -- the plausible fallback was the bug.)
	if otelWellKnown[DefaultGenAISystem] {
		t.Errorf("DefaultGenAISystem = %q, a well-known provider value -- the fallback must not be a plausible provider", DefaultGenAISystem)
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

// litellmProvidersUnmapped is the documented exception list for
// TestProviderTableCoversLiteLLMProviders: providers LiteLLM knows about
// that this table deliberately does not map. An unmapped provider does
// not fall through to a plausible-but-wrong value -- buildGenAI emits
// DefaultGenAISystem ("unknown") for it, which is the marker working as
// designed. Add a provider to the table (with a vocabulary-legal value)
// when this deployment starts routing it; until then "unknown" is the
// honest answer.
//
// Grouped by why they are unmapped; the grouping is indicative, the
// membership is what the test enforces.
var litellmProvidersUnmapped = map[string]bool{
	// Chat-capable providers this deployment does not route. If one of
	// these shows up in config.yaml, the spend rows surface as "unknown"
	// and the gap is visible -- which is exactly what did not happen for
	// ollama_chat.
	"a2a": true, "a2a_agent": true, "ai21": true, "ai21_chat": true,
	"aiml": true, "aiohttp_openai": true, "amazon_nova": true,
	"anthropic_text": true, "apertis": true, "azure_text": true,
	"baseten": true, "bedrock_mantle": true, "bytez": true,
	"cerebras": true, "charity_engine": true, "chatgpt": true,
	"chutes": true, "clarifai": true, "cloudflare": true,
	"codestral": true, "cohere_chat": true, "cometapi": true,
	"compactifai": true, "cursor": true, "darkbloom": true,
	"dashscope": true, "databricks": true, "datarobot": true,
	"deepinfra": true, "docker_model_runner": true, "empower": true,
	"featherless_ai": true, "fireworks_ai": true, "friendliai": true,
	"galadriel": true, "gdc": true, "gigachat": true, "github": true,
	"github_copilot": true, "gradient_ai": true, "heroku": true,
	"huggingface": true, "hyperbolic": true, "inception": true,
	"lambda_ai": true, "langflow": true, "langgraph": true,
	"lemonade": true, "libertai": true, "litellm_agent": true,
	"manus": true, "maritalk": true, "meta": true, "meta_llama": true,
	"minimax": true, "modelscope": true, "moonshot": true, "morph": true,
	"nano-gpt": true, "nebius": true, "neosantara": true,
	"nlp_cloud": true, "novita": true, "nscale": true, "nvidia_nim": true,
	"oci": true, "oobabooga": true, "ovhcloud": true, "parasail": true,
	"petals": true, "pinstripes": true, "poe": true, "predibase": true,
	"publicai": true, "ragflow": true, "replicate": true,
	"sagemaker": true, "sagemaker_chat": true, "sagemaker_nova": true,
	"sambanova": true, "sap": true, "scaleway": true, "snowflake": true,
	"synthetic": true, "tencent": true, "tensormesh": true,
	"text-completion-codestral": true, "text-completion-inception": true,
	"text-completion-openai": true, "triton": true, "v0": true,
	"vercel_ai_gateway": true, "vertex_ai_beta": true, "volcengine": true,
	"wandb": true, "watsonx_text": true, "xiaomi_mimo": true,
	"xinference": true, "zai": true,

	// Non-chat providers (embedding, audio, image, vector stores). This
	// proxy serves chat completions only; none of these can appear on a
	// real spend row here.
	"assemblyai": true, "aws_polly": true, "black_forest_labs": true,
	"deepgram": true, "elevenlabs": true, "fal_ai": true, "infinity": true,
	"jina_ai": true, "milvus": true, "nvidia_riva": true,
	"openai_like": true, "pg_vector": true, "recraft": true,
	"reducto": true, "runwayml": true, "s3_vectors": true, "soniox": true,
	"stability": true, "topaz": true, "voyage": true,

	// LiteLLM-internal or meta entries, not model providers.
	"auto_router": true, "custom": true, "custom_openai": true,
	"dotprompt": true, "helicone": true, "humanloop": true,
	"langfuse": true, "litellm_proxy": true,
}

// TestProviderTableCoversLiteLLMProviders is the input-side check whose
// absence let this bug ship: TestGenAISystemValuesAreInTheOTelVocabulary
// validates the table's OUTPUTS against the spec vocabulary, but nothing
// validated that the table's INPUTS cover the prefixes LiteLLM actually
// emits -- so "ollama_chat", a real prefix, reached production unmapped
// and fell through to the plausible fallback.
//
// The fixture is a committed snapshot of LiteLLM's LlmProviders enum
// (testdata/litellm-providers.txt -- refresh it on every LiteLLM
// upgrade; the file header has the one-liner). The rule: every provider
// LiteLLM knows about must be either mapped in the table or listed in
// litellmProvidersUnmapped as a deliberate decision. A LiteLLM upgrade
// that adds a provider fails this test until a human makes that decision,
// instead of silently emitting the fallback for it.
//
// Both directions are checked: a table key or exception that is not in
// the enum is a typo or a stale entry, and fails too.
func TestProviderTableCoversLiteLLMProviders(t *testing.T) {
	raw, err := os.ReadFile("testdata/litellm-providers.txt")
	if err != nil {
		t.Fatalf("reading provider fixture: %v", err)
	}
	var providers []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		providers = append(providers, line)
	}
	if len(providers) < 100 {
		t.Fatalf("provider fixture has only %d entries -- expected LiteLLM's full enum (100+); is the file truncated?", len(providers))
	}

	for _, p := range providers {
		if _, mapped := litellmProviderToGenAISystem[p]; mapped {
			continue
		}
		if !litellmProvidersUnmapped[p] {
			t.Errorf("LiteLLM provider %q is neither mapped in litellmProviderToGenAISystem nor listed in litellmProvidersUnmapped -- map it or deliberately exclude it", p)
		}
	}
	for key := range litellmProviderToGenAISystem {
		found := false
		for _, p := range providers {
			if p == key {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("table key %q is not in LiteLLM's LlmProviders enum -- typo, or LiteLLM renamed it (refresh testdata/litellm-providers.txt)", key)
		}
	}
	for exc := range litellmProvidersUnmapped {
		found := false
		for _, p := range providers {
			if p == exc {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("exception %q is not in LiteLLM's LlmProviders enum -- stale entry (refresh testdata/litellm-providers.txt)", exc)
		}
	}
}
