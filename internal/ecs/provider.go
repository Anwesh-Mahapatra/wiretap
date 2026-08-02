package ecs

import "strings"

// DefaultGenAISystem is what gen_ai.system falls back to when nothing in
// the event identifies a provider -- no gateway-reported provider, and no
// model-name route prefix the table recognises.
//
// It is deliberately NOT a plausible provider value. This constant used to
// be "groq", on the grounds that this deployment routed everything to Groq
// -- which turned every unrecognised provider into a confident wrong
// answer the day config.yaml gained a second model_list entry: six
// Ollama-served documents labelled "groq" on both planes, caught only
// because a human read them (see notes.md). A fallback that returns a
// plausible value hides the gap it is covering: nothing ever looks wrong,
// so nobody looks. "unknown" cannot be mistaken for data, is grep-able as
// a coverage audit (`gen_ai.system: "unknown"` lists every gap), and keeps
// the field present on every document -- omitting it would let
// `NOT gen_ai.system: X` clauses silently match the gaps instead.
//
// The value is spec-legal: the OpenTelemetry registry's rule for
// gen_ai.system is that a well-known value MUST be used where one applies,
// and a custom value MAY be used otherwise. No well-known value means
// "this mapper could not identify a provider", so a custom one it is.
const DefaultGenAISystem = "unknown"

// litellmProviderToGenAISystem maps LiteLLM's route prefix -- the part
// before the slash in a model string like "groq/llama-3.3-70b-versatile"
// -- onto the corresponding gen_ai.system value.
//
// This table exists because the two vocabularies are NOT the same, and a
// naive strings.Cut on "/" produces values that are not in the spec at all
// for a majority of providers. Checked against the OpenTelemetry Gen AI
// attributes registry (the spec docs/reference/ecs-gen_ai.md itself points
// at for this field) on 2026-08-01:
//
//	LiteLLM prefix   naive split gives   the actual spec value
//	bedrock/         "bedrock"           "aws.bedrock"
//	azure/           "azure"             "azure.ai.openai"
//	azure_ai/        "azure_ai"          "azure.ai.inference"
//	vertex_ai/       "vertex_ai"         "gcp.vertex_ai"
//	gemini/          "gemini"            "gcp.gemini"
//	mistral/         "mistral"           "mistral_ai"
//	watsonx/         "watsonx"           "ibm.watsonx.ai"
//
// Only groq, openai, anthropic, cohere, deepseek and perplexity happen to
// round-trip unchanged -- which is precisely why deriving this by string
// splitting would look correct in this deployment (groq) and silently emit
// off-spec values the moment anything else was routed.
//
// Prefixes absent from this map are deliberately NOT passed through: an
// unrecognised prefix means either a provider this table has not been
// updated for, or something that is not a provider prefix at all. Emitting
// it raw would put an unvalidated string into a field whose whole value is
// that its vocabulary is known. See deriveGenAISystem's ok return.
var litellmProviderToGenAISystem = map[string]string{
	"anthropic":  "anthropic",
	"azure":      "azure.ai.openai",
	"azure_ai":   "azure.ai.inference",
	"bedrock":    "aws.bedrock",
	"cohere":     "cohere",
	"deepseek":   "deepseek",
	"gemini":     "gcp.gemini",
	"groq":       "groq",
	"mistral":    "mistral_ai",
	"openai":     "openai",
	"perplexity": "perplexity",
	"vertex_ai":  "gcp.vertex_ai",
	"watsonx":    "ibm.watsonx.ai",
	"xai":        "xai",

	// Self-hosted and open-weight serving -- the plausible next backends
	// for this deployment. No OTel well-known value applies to any of
	// these, so the mapped values are the custom values the spec permits
	// (a well-known value MUST be used where one applies; otherwise a
	// custom value MAY be used). They name the serving *product* and
	// collapse LiteLLM's route variants: ollama_chat is Ollama's chat
	// endpoint and hosted_vllm a remote vLLM server -- same product,
	// reached differently. "ollama" in particular is the entry whose
	// absence labelled six Ollama-served documents "groq".
	"ollama":      "ollama",
	"ollama_chat": "ollama",
	"vllm":        "vllm",
	"hosted_vllm": "vllm",
	"lm_studio":   "lm_studio",
	"llamafile":   "llamafile",
	"openrouter":  "openrouter",
	"together_ai": "together_ai",
}

// deriveGenAISystem resolves gen_ai.system from the best evidence
// available, in descending order of trust:
//
//  1. gatewayProvider -- LiteLLM's own custom_llm_provider field, present
//     on every successful gateway record. This is the proxy stating which
//     provider it routed to, not an inference from a string.
//  2. The route prefix on a model name, e.g. "groq/llama-3.3-70b-versatile".
//     This is all the content plane ever has, and real captured Langfuse
//     data does carry the prefix on successful generations.
//
// ok is false when nothing recognised a provider, and system is then "".
// The function does NOT apply a fallback: it used to take one as a
// parameter and return it with ok=false, and the single call site
// discarded the ok with `_` -- storing the fallback as though it had been
// derived. A safety return no caller consumes is not a safety mechanism,
// and the compiler cannot help: discarding a return with _ is legal and
// intentional-looking. The fallback therefore now lives at the call site
// (buildGenAI), where leaving it out is impossible to do silently.
func deriveGenAISystem(gatewayProvider, responseModel, requestModel string) (system string, ok bool) {
	if s, found := litellmProviderToGenAISystem[strings.ToLower(strings.TrimSpace(gatewayProvider))]; found {
		return s, true
	}
	// Prefer the model that answered; fall back to the one requested. On a
	// refused request only the requested model exists, and it carries no
	// prefix -- so this correctly finds nothing and falls through.
	for _, m := range []string{responseModel, requestModel} {
		if s, found := providerFromModelPrefix(m); found {
			return s, true
		}
	}
	return "", false
}

// providerFromModelPrefix extracts the LiteLLM route prefix from a model
// string and maps it. Returns false for an unprefixed model (the common
// case on this deployment's content plane for refused requests) and for a
// prefix this table does not recognise.
func providerFromModelPrefix(model string) (string, bool) {
	prefix, _, found := strings.Cut(model, "/")
	if !found || prefix == "" {
		return "", false
	}
	s, ok := litellmProviderToGenAISystem[strings.ToLower(prefix)]
	return s, ok
}

// callTypeToOperation maps LiteLLM's call_type onto gen_ai.operation.name.
// Values checked against the OpenTelemetry Gen AI registry on 2026-08-01:
// chat, embeddings and text_completion are all documented allowed values.
//
// LiteLLM prefixes async variants with "a" (acompletion, aembedding), and
// uses "completion" for the chat-completions route rather than the legacy
// text-completions one -- so "completion" maps to "chat", and the legacy
// route appears as "text_completion".
var callTypeToOperation = map[string]string{
	"acompletion":      "chat",
	"completion":       "chat",
	"aembedding":       "embeddings",
	"embedding":        "embeddings",
	"atext_completion": "text_completion",
	"text_completion":  "text_completion",
}

// DefaultGenAIOperation is the operation this deployment's content plane
// assumes.
//
// Unlike gen_ai.system, a constant here is defensible on the content
// plane, and the reason is a real asymmetry rather than convenience:
// Langfuse types every LLM call as a GENERATION observation and carries no
// field distinguishing a chat completion from an embeddings call. There is
// nothing to derive from. Inventing a distinction Langfuse does not record
// would be the same "plausible value from the wrong place" move this
// project refuses elsewhere.
//
// The gateway plane does not use this: LiteLLM reports call_type per
// record, so deriveOperation resolves it from real data. That means the
// two planes can disagree about operation for the same request, and that
// disagreement is honest -- one of them measured it and one of them
// assumed it.
const DefaultGenAIOperation = "chat"

// deriveOperation resolves gen_ai.operation.name from LiteLLM's call_type,
// falling back to the supplied default. A refused request has an empty
// call_type -- LiteLLM never got far enough to have one -- so the fallback
// is what a blocked request gets, which is correct: the caller was
// attempting a chat completion whether or not it was allowed to.
func deriveOperation(callType, fallback string) string {
	if op, ok := callTypeToOperation[strings.ToLower(strings.TrimSpace(callType))]; ok {
		return op
	}
	return fallback
}
