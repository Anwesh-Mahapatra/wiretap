// Package model defines wiretap's source-agnostic intermediate
// representation of one LLM interaction: LLMEvent. Every ingest source
// (Langfuse today; a second source such as LiteLLM's own gateway logs in a
// later module) parses into this same shape, and every output mapper (ECS
// today) reads only from this shape -- never from a source's own JSON.
//
// That indirection is the point: internal/parse knows Langfuse's field
// names, internal/ecs knows ECS's field names, and neither package needs to
// know the other exists. Adding a second source means writing a second
// parser that produces an LLMEvent; it does not touch the mapper. Adding a
// second output format means writing a second mapper that reads an
// LLMEvent; it does not touch any parser.
package model

import "time"

// Message is one turn of an ordered conversation. Order is preserved
// exactly as the source reported it. Collapsing this down to, say, "the
// last system message" and "the last user message" is a presentation
// decision that belongs to a mapper (see internal/ecs's llm.system_prompt /
// llm.user_prompt), not something baked into the intermediate
// representation -- a lossy IR here would have to be rewritten the day
// multi-turn conversations or tool calls need representing.
type Message struct {
	Role    string
	Content string
}

// Outcome is wiretap's own ground-truth label for a scenario request. It is
// never derived from anything a real caller controls, and a mapper must
// never let it leak into a field a detection rule would naturally query
// (see notes.md's "quarantined ground truth" discussion). The empty string
// means "not a wiretap scenario trace" -- e.g. real traffic, once this
// pipeline ingests production data -- not "outcome unknown."
type Outcome string

const (
	OutcomeBenign    Outcome = "benign"
	OutcomeInjection Outcome = "injection"
	OutcomeTruncated Outcome = "truncated"
)

// Source identifies which upstream system produced an LLMEvent.
type Source string

const (
	SourceLangfuse Source = "langfuse"
)

// LLMEvent is one LLM interaction -- one request and, if it completed, its
// response -- in a shape that answers to neither its input format
// (Langfuse's JSON) nor its output format (ECS). See the package doc.
//
// Numeric fields the source may genuinely not report (as opposed to
// reporting as zero) are pointers. A nil *int here means "the source never
// told us," not "the source told us zero" -- collapsing that distinction
// would let missing token-usage data masquerade as a free request, and
// missing cost data as a $0 one.
type LLMEvent struct {
	// Identity
	TraceID     string
	SessionID   string
	UserID      string
	TraceName   string
	ProjectID   string
	Environment string

	// Timing
	RequestTimestamp time.Time      // when the request was made
	IngestTimestamp  time.Time      // when the source system recorded/ingested it
	Duration         *time.Duration // request wall time; nil if the source didn't report one

	// Request
	RequestModel string // model the caller asked for
	MaxTokens    *int
	Temperature  *float64
	Messages     []Message // full ordered conversation, roles preserved

	// Response
	OutputContent string
	OutputRole    string
	FinishReasons []string // e.g. ["stop"], ["length"]; nil means not reported
	ResponseID    string
	ResponseModel string // model that actually answered -- may differ from RequestModel on fallback/routing

	// Usage
	InputTokens  *int // summed across every GENERATION observation, when the source reports detail -- see internal/parse's package doc
	OutputTokens *int // summed across every GENERATION observation
	TotalCost    *float64
	// GenerationCount is how many GENERATION observations contributed to
	// InputTokens/OutputTokens/ResponseModel/ResponseID. Always a real,
	// known value (0 when the source gave no observation detail at all,
	// or genuinely had no GENERATION observations) -- never a pointer,
	// because "zero generations" is itself meaningful, not "unknown."
	// Exists so a summed token count is never presented without the
	// context of how many calls it summarizes -- see internal/ecs's
	// llm.generation_count.
	GenerationCount int

	// Classification
	Outcome       Outcome
	Tags          []string
	IsHealthCheck bool

	// Provenance
	Source       Source
	SourceRef    string // path or URL back to this record in its source system's own UI (e.g. Langfuse's htmlPath); empty if the source has no such concept
	SourceRecord []byte // the original raw record this event was parsed from (e.g. one NDJSON line), kept for debugging and replay
}
