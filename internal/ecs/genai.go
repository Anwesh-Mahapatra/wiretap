package ecs

// genAI holds every gen_ai.* field this mapper emits. Each was checked
// against docs/reference/ecs-gen_ai.md before being added; the doc line
// cited below is the line of that file's field table describing it (as of
// the file's current content):
//
//	gen_ai.operation.name        keyword  doc line 33
//	gen_ai.system                keyword  doc line 49 (OTel equivalent: gen_ai.provider.name)
//	gen_ai.request.model         keyword  doc line 39
//	gen_ai.request.max_tokens    integer  doc line 38
//	gen_ai.response.model        keyword  doc line 48
//	gen_ai.response.id           keyword  doc line 47
//	gen_ai.response.finish_reasons  nested (array of keyword values, per its own example ["stop","length"])  doc line 46
//	gen_ai.usage.input_tokens    integer  doc line 54
//	gen_ai.usage.output_tokens   integer  doc line 55
//
// (Line numbers as of docs/reference/ecs-gen_ai.md's current content --
// re-check these if that file's header note is ever edited, since that
// shifts every line below it.)
//
// Every numeric field is a pointer so a value this project's Langfuse data
// genuinely doesn't carry (see internal/parse's package doc for exactly
// which ones, and why) is omitted from the document entirely rather than
// serialized as a fabricated 0 -- see MapConfirmsNoZeroSubstitution in
// map_test.go.
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
	Model         string   `json:"model,omitempty"`
	ID            string   `json:"id,omitempty"`
	FinishReasons []string `json:"finish_reasons,omitempty"`
}

type genAIUsage struct {
	InputTokens  *int `json:"input_tokens,omitempty"`
	OutputTokens *int `json:"output_tokens,omitempty"`
}
