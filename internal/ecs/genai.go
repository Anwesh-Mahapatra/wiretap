package ecs

// genAI holds every gen_ai.* field this mapper emits. Each field name and
// type below was checked against docs/reference/ecs-gen_ai.md before being
// added -- but that check used to be recorded as a doc *line number* in
// this comment, and line numbers broke the first time anyone edited that
// file (a header note shifted every citation by 9 lines, silently). Field
// names don't shift. TestGenAIFieldsExistInReferenceDoc (genai_test.go)
// reads docs/reference/ecs-gen_ai.md at test time and asserts every field
// this struct can produce -- derived from the struct itself via
// reflection, not a second hand-maintained list that could drift from it
// -- actually appears there with a compatible type. Editing or drifting
// from the reference doc now fails a test instead of silently producing a
// plausible-looking wrong schema.
//
// gen_ai.response.finish_reasons is deliberately absent from this struct:
// confirmed genuinely unavailable from this project's Langfuse data by
// direct inspection of a captured trace-detail response (grepped for
// "finish"/"stop"/"length" in every plausible location -- the observation
// itself, nested in output, in metadata -- nothing). See notes.md's
// worked example. Faking it from a plausible-but-wrong location would be
// exactly the kind of silently-wrong telemetry this project's own
// detection-engineering notes warn against.
//
// Every numeric field is a pointer so a value this project's Langfuse data
// genuinely doesn't carry (see internal/parse's package doc for exactly
// which ones, and why) is omitted from the document entirely rather than
// serialized as a fabricated 0 -- see
// TestMap_NoGenAIFieldEmittedAsZeroSubstituteForMissing in map_test.go.
type genAI struct {
	Operation *genAIOperation `json:"operation,omitempty"`
	// System is gen_ai.system, checked against the OpenTelemetry Gen AI
	// semantic conventions registry (the spec ECS's own doc points at) on
	// 2026-07-29: "groq" is a documented well-known provider value
	// (alongside openai, anthropic, aws.bedrock, etc.), not a made-up one.
	System   string         `json:"system,omitempty"`
	Request  *genAIRequest  `json:"request,omitempty"`
	Response *genAIResponse `json:"response,omitempty"`
	Usage    *genAIUsage    `json:"usage,omitempty"`
}

type genAIOperation struct {
	Name string `json:"name,omitempty"`
}

type genAIRequest struct {
	Model     string `json:"model,omitempty"`
	MaxTokens *int   `json:"max_tokens,omitempty"`
}

type genAIResponse struct {
	Model string `json:"model,omitempty"`
	ID    string `json:"id,omitempty"`
}

type genAIUsage struct {
	InputTokens  *int `json:"input_tokens,omitempty"`
	OutputTokens *int `json:"output_tokens,omitempty"`
}
