package ecs

// llm is NOT an ECS field group. ECS's gen_ai.* namespace deliberately has
// no field for prompt or completion text -- OpenTelemetry keeps message
// content out of span attributes, since it's frequently sensitive and
// frequently large. This project needs that content for its detections
// (the canary-token check greps llm.output; the injection-phrasing check
// greps llm.user_prompt), so it lives here instead, under a namespace this
// project invented and clearly separates from ECS proper.
//
// If ECS ever adds a real content field for Gen AI events, llm.* should be
// revisited -- the fields below exist to fill a gap, not because this
// project prefers its own schema to ECS's.
type llm struct {
	// SystemPrompt is the content of the *last* message with role
	// "system". Content is the point of this namespace, so unlike the
	// gen_ai.* fields above, these are never omitted for being empty --
	// an empty prompt is itself a fact worth keeping (e.g. a trace with no
	// system message at all), not an absence to hide.
	SystemPrompt string `json:"system_prompt"`
	// UserPrompt is the content of the *last* message with role "user" --
	// last, not first, because in a multi-turn conversation the current
	// turn (not the opening one) is what a detection cares about.
	UserPrompt string `json:"user_prompt"`
	Output     string `json:"output"`
	OutputRole string `json:"output_role"`
	// Messages is the full ordered conversation, JSON-encoded as a single
	// string, preserving the turn-by-turn fidelity that SystemPrompt/
	// UserPrompt alone discard. Empty string if there were no messages.
	Messages     string `json:"messages"`
	MessageCount int    `json:"message_count"`
	OutputLength int    `json:"output_length"`
	// TotalCostUSD is another ECS gap, not a content field: the Gen AI
	// field group (docs/reference/ecs-gen_ai.md) has no cost field at all.
	// Pointer, not a plain float64, because a genuinely-unreported cost
	// (Langfuse's totalCost was null) must stay absent from the document
	// rather than serialize as a fabricated $0 -- the same zero-vs-absent
	// rule the gen_ai.* fields follow, applied here because the risk
	// (mistaking "unknown" for "free") is identical even though this isn't
	// a gen_ai.* field.
	TotalCostUSD *float64 `json:"total_cost_usd,omitempty"`
}

// llmMessage is llm.messages' own element shape once JSON-decoded --
// deliberately not model.Message, which carries no JSON tags of its own
// (see internal/model's package doc: it answers to neither an input nor an
// output format).
type llmMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
