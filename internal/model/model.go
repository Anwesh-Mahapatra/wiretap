// Package model defines wiretap's source-agnostic intermediate
// representation of one LLM interaction: LLMEvent. Every ingest source
// (Langfuse today; a second source such as LiteLLM's own gateway logs in a
// later module) parses into this same shape, and every output mapper (ECS
// today) reads only from this shape -- never from a source's own JSON.
//
// That indirection is the point: internal/parse knows Langfuse's field
// names, internal/ecs knows ECS's field names, and neither package needs to
// know the other exists.
//
// # How that claim actually held, measured
//
// This package used to promise more than it could deliver. The original
// wording was that adding a second source "does not touch the mapper" and
// that internal/ecs "doesn't change at all." When the gateway source
// actually arrived, that turned out to be half right, and the half it got
// wrong is worth stating precisely rather than quietly rewording.
//
// What held completely: internal/ecs has never seen a LiteLLM field name,
// exactly as it has never seen a Langfuse one. Neither parser knows the
// other exists. Every ECS field describing a fact both planes report --
// trace ID, models, token counts, cost, status, timing, provenance: 20 of
// them -- was reused by the gateway mapper with no change to its
// definition, and the content plane's golden files were untouched by the
// gateway source's arrival.
//
// What did not hold: the gateway reports facts the content plane cannot,
// and a fact you have no field for cannot be expressed no matter how much
// indirection sits in front of it. Seven new ECS fields had to be added to
// internal/ecs for the gateway source (event.type, event.action,
// error.type, error.code, http.response.status_code, llm.key.alias,
// llm.key.hash), plus one structural change: event.dataset had been
// hardcoded to "wiretap.langfuse" in the mapper and had to become a
// parameter.
//
// The distinction that was missed the first time: an intermediate
// representation insulates the output format from the *input format's
// churn*. It cannot insulate it from *vocabulary growth*. Those are
// different problems and only the first one is solved here. That is still
// a real and load-bearing benefit -- it is why two parsers can share one
// mapper's common-field builder at all -- but it is a narrower claim than
// the one this comment used to make.
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
	SourceLiteLLM  Source = "litellm"
)

// Status is whether the request this event describes actually completed.
// It is derived entirely from what the source reported -- for Langfuse,
// from observation level ("ERROR" vs anything else) -- and is never
// wiretap's own judgement about the request.
//
// Do not confuse this with Outcome. Outcome is wiretap's *ground-truth
// scenario label* ("was this prompt an injection attempt"), quarantined
// under labels.* and never queryable by a detection. Status is an
// observed fact about the request's fate ("did it get an answer"), and
// detections are expressly meant to key on it. They answer different
// questions and an injection scenario can perfectly well succeed while a
// benign one gets blocked.
type Status string

const (
	// StatusUnknown means the source gave no basis to decide -- e.g. an
	// archive line whose observations are bare ID strings rather than
	// full objects (see internal/parse's decodeObservations), so no
	// level was ever visible. It is NOT "the request failed", and it is
	// not a synonym for the empty string meaning "no data": it is the
	// honest answer when detail was never fetched.
	StatusUnknown Status = ""
	StatusSuccess Status = "success"
	StatusFailure Status = "failure"
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
	//
	// RequestTimestamp is what the source calls "when this happened", and
	// the two sources mean different instants by it: LiteLLM means the
	// request start, Langfuse means when its callback fired (after the
	// response for a success, near the start for a refusal). It becomes
	// @timestamp, and its meaning is documented per dataset rather than
	// pretended to be uniform.
	//
	// StartTime and EndTime are the request's own boundaries, and unlike
	// RequestTimestamp they mean the same instant on both planes --
	// measured agreement is sub-millisecond, because both come from the
	// same LiteLLM process observing the same request. They are what
	// cross-plane correlation compares. Zero when the source did not
	// report them. See docs/CORRELATION.md §5.
	RequestTimestamp time.Time      // -> @timestamp; source-specific meaning
	StartTime        time.Time      // -> event.start; comparable across sources
	EndTime          time.Time      // -> event.end; comparable across sources
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

	// Status / failure detail
	//
	// Status is whether the request completed at all (see Status's own doc
	// comment for why this is not the same thing as Outcome).
	// StatusMessage is the source's own words for why it didn't -- for
	// Langfuse, an ERROR observation's statusMessage, which for this
	// deployment carries LiteLLM's enforcement text verbatim, e.g.
	// "Budget has been exceeded! Key=bob (sk-...9SfA) ...". Empty when
	// nothing failed or the source reported no message.
	//
	// ErroredGenerationCount is how many GENERATION observations the
	// source reported at ERROR level. It is deliberately separate from
	// GenerationCount rather than folded into it: a blocked request
	// produces error records but zero completions, and collapsing the two
	// would make "how many times did the model actually answer" and "how
	// many times was this request rejected" indistinguishable -- which is
	// precisely the distinction the gateway plane exists to sharpen.
	Status                 Status
	StatusMessage          string
	ErroredGenerationCount int

	// Classification
	Outcome       Outcome
	Tags          []string
	IsHealthCheck bool

	// Gateway is the facts only a gateway plane can report, and is nil for
	// every event from a source that is not one (today: every Langfuse
	// event). See GatewayDetail for why these are nested behind a pointer
	// instead of sitting flat alongside the fields above.
	Gateway *GatewayDetail

	// Provenance
	Source       Source
	SourceRef    string // path or URL back to this record in its source system's own UI (e.g. Langfuse's htmlPath); empty if the source has no such concept
	SourceRecord []byte // the original raw record this event was parsed from (e.g. one NDJSON line), kept for debugging and replay
}

// GatewayDetail is what a *gateway* knows about a request that a content
// tracer structurally cannot: which credential paid, what HTTP status the
// caller received, and -- when the request was refused -- the machine-
// readable class of refusal rather than a sentence of English.
//
// # Why nested behind a pointer, rather than flat on LLMEvent
//
// The alternative considered was adding these eight fields directly to
// LLMEvent and letting Source discriminate. Both shapes carry the same
// data; the difference is what happens when someone writes a mapper.
//
// Flat, LLMEvent grows to ~40 fields of which a third are meaningful for
// exactly one of two sources, and nothing in the type says which. A mapper
// that reads KeyAlias for a Langfuse event gets "", emits an empty
// llm.key.alias on every content document, and produces precisely the
// dead-schema failure notes.md already documents once (the empty gen_ai.*
// fields: a field that validated, tested green, and meant nothing).
//
// Nested, `ev.Gateway == nil` is one check that answers the question for
// all eight fields at once, and it is impossible to reach KeyAlias without
// having acknowledged the field might not apply. That is the whole benefit
// and it is worth one level of indirection.
//
// # Why not a separate GatewayEvent type
//
// A sibling type would duplicate the ~14 fields that are genuinely the
// same concept on both planes -- TraceID, the timing triple, request and
// response model, token counts, cost, Status, StatusMessage, and all of
// provenance. Duplication there is not free: it is two definitions of
// "what a request costs" that must be changed together forever, and
// internal/ecs would need either two mappers sharing no code or an
// interface that is this struct's shared core wearing a different hat.
// The cost of the rejected option is real but it is paid in a place that
// is easy to get wrong quietly, which is the worse trade.
//
// # Why the content-only fields are NOT symmetrically nested
//
// Messages, OutputContent, GenerationCount and friends stay flat on
// LLMEvent while these are nested, which is an asymmetry on purpose. The
// prompt and the response are what an LLM interaction *is*; the credential
// that authorised it and the status code it received are facts about the
// interaction's transport and authorization. The asymmetry tracks that
// distinction rather than mere convenience -- though if a third source
// ever arrives, that is the moment to revisit it rather than nest a third
// thing behind a third pointer.
type GatewayDetail struct {
	// RequestID is the gateway's own per-attempt identifier. On a
	// successful request LiteLLM sets it to the provider's completion ID
	// ("chatcmpl-..."), which makes it a usable secondary join key; on a
	// refused request it is an unrelated UUID, which is exactly why it
	// cannot be the primary one. See docs/CORRELATION.md §2.
	RequestID string
	// CallID is the gateway's stable per-attempt ID regardless of outcome
	// (LiteLLM's litellm_call_id). Unlike RequestID it means the same
	// thing on success and failure.
	CallID string

	// KeyAlias and KeyHash identify *which credential paid*, as distinct
	// from LLMEvent.UserID, which is who asked. These are different
	// concepts and conflating them into user.id would make "two people
	// sharing a key" and "one person using two keys" indistinguishable --
	// destroying the credential-sharing detection before it is written.
	//
	// KeyAlias is absent when the attempted key was never valid: there is
	// no name for a key that does not exist. KeyHash is present even then,
	// and is the hash of what was *attempted*, which is what makes
	// credential-spray clustering possible. Neither is ever the key.
	KeyAlias string
	KeyHash  string
	TeamID   string

	// HTTPStatusCode is what the caller actually received. Pointer because
	// 0 is not a status code, and a gateway record that somehow lacks one
	// must not claim the request returned zero.
	HTTPStatusCode *int
	// ErrorClass is the machine-readable refusal type
	// ("BudgetExceededError", "KeyNotFoundError") -- the field detections
	// group on, and the single thing the content plane cannot supply
	// without string-matching English. ErrorCode is the status as the
	// gateway reported it, kept separate from HTTPStatusCode because it is
	// the source's own string and may not always be numeric.
	ErrorClass string
	ErrorCode  string

	// Provider is the gateway's own answer to "who served this"
	// (LiteLLM's custom_llm_provider, e.g. "groq"). Authoritative, and
	// notably better than deriving it from a model-name prefix, which is
	// all the content plane can do. Empty on a refused request, which
	// never routed anywhere.
	Provider string

	// AttemptedRetries is the gateway's *own* upstream retry count -- not
	// the client's. Pointer because LiteLLM reports 0 on success and null
	// on failure, and those must stay distinguishable. Note the client's
	// retry count (X-Stainless-Retry-Count) reaches neither plane: a
	// client that retried three times produces three separate gateway
	// records sharing one TraceID, which is how retry fan-out is counted.
	AttemptedRetries *int

	// RequesterIP is present only on successful requests in this
	// deployment -- LiteLLM records null for it on every refusal, verified
	// across 18 failure records. Any detection that wants to cluster
	// *failures* by origin therefore cannot use it, and must cluster on
	// KeyHash instead. Empty means absent, not 0.0.0.0.
	RequesterIP string

	// CallType is the gateway's operation name ("acompletion"). Empty on a
	// refused request, which never got far enough to have one.
	CallType string
}
