// Package ecs maps a model.LLMEvent onto an ECS-shaped document ready for
// Elasticsearch. It is the only package in this project that ever writes a
// gen_ai.* or other ECS field name -- every one of them was checked against
// docs/reference/ecs-gen_ai.md (or, for core ECS fields outside the Gen AI
// field group, against Elastic's own ECS reference docs) before being added
// here. See Map's doc comment for the field-by-field citation.
//
// Where ECS ends: the gen_ai.* namespace deliberately has no field for
// prompt or completion text -- OpenTelemetry keeps message content out of
// span attributes on purpose, since it's often sensitive and often large.
// Prompt/output content in this project therefore lives under llm.*, a
// namespace this project invented and documents as non-ECS wherever it
// appears. Nothing is ever written to a gen_ai.* field because it merely
// looks similar to where content "should" go -- see llm.go's package doc
// for the full rationale, and revisit that decision if ECS ever adds a
// content field of its own.
package ecs

// ECSVersion is the ECS schema version this mapper targets, pinned so a
// future ECS release is a deliberate, reviewed bump rather than silent
// drift. Chosen to match this project's Elasticsearch/Kibana version
// (9.4.4, see docker-compose.yml) -- confirmed against elastic/ecs's own
// latest release (v9.4.0) on 2026-07-29.
const ECSVersion = "9.4.0"

// Document is one ECS-shaped record built from a model.LLMEvent, ready to
// be marshaled to JSON and bulk-indexed into Elasticsearch (see
// internal/esink). Fields nest the way ECS itself nests them -- trace.id
// becomes {"trace":{"id":...}} -- because that's what lets Elasticsearch's
// standard object-type mapping resolve a nested JSON nested object to a
// dotted field name. A flat JSON object with a literal dotted key
// ("trace.id": "...") is a different, non-standard thing that Elasticsearch
// does not treat the same way without extra configuration this project
// doesn't use.
type Document struct {
	Timestamp string    `json:"@timestamp,omitempty"`
	ECS       ecsMeta   `json:"ecs"`
	Event     event     `json:"event"`
	Trace     *idField  `json:"trace,omitempty"`
	Session   *idField  `json:"session,omitempty"`
	User      *idField  `json:"user,omitempty"`
	GenAI     *genAI    `json:"gen_ai,omitempty"`
	HTTP      *ecsHTTP  `json:"http,omitempty"`
	Error     *ecsError `json:"error,omitempty"`
	LLM       llm       `json:"llm"`
	Labels    labels    `json:"labels"`
	Related   *related  `json:"related,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
}

// ecsHTTP holds ECS core http.* fields. Verified against Elastic's ECS
// "http" field group reference (elastic.co/docs/reference/ecs/ecs-http)
// on 2026-08-01: http.response.status_code is type long, described simply
// as "HTTP response status code."
//
// Only the gateway plane populates this. The content plane has no concept
// of an HTTP status -- Langfuse records what a callback told it, not what
// the caller received -- so a content document carries no http object at
// all rather than an empty one.
type ecsHTTP struct {
	Response *ecsHTTPResponse `json:"response,omitempty"`
}

type ecsHTTPResponse struct {
	// StatusCode is a pointer because 0 is not a status code. A gateway
	// record whose error_code is non-numeric yields no status rather than
	// a fabricated zero that would index as a real value.
	StatusCode *int `json:"status_code,omitempty"`
}

// related holds ECS related.* fields -- deliberately heterogeneous bags of
// identifiers that exist so one pivot query can find an entity however it
// was recorded. Verified against Elastic's ECS "related" field group
// reference on 2026-07-31: related.user is keyword, described as "All the
// user names or other user identifiers seen on the event."
//
// This carries both the end-user identity (who asked) and the virtual key
// alias (which credential paid). Those are different concepts and are
// mapped to different fields elsewhere -- user.id and llm.key.alias -- on
// purpose; related.user is what lets an analyst pivot on either without
// having to know which kind of identifier they are holding. Because ECS
// defines related.* as an unordered set of identifiers rather than a
// semantic claim, putting both here asserts nothing false.
type related struct {
	User []string `json:"user,omitempty"`
}

// ecsError holds ECS core error.* fields. Verified against Elastic's ECS
// "error" field group reference (elastic.co/docs/reference/ecs/ecs-error)
// on 2026-07-31:
//
//   - error.message (match_only_text) -- "Error message." Carries the
//     source's own explanation of why a request failed; for this
//     project's Langfuse data that is an ERROR observation's
//     statusMessage, which is LiteLLM's enforcement text verbatim.
//
//   - error.type (keyword) -- "The type of the error, for example the
//     class name of the exception." An exact fit for LiteLLM's
//     error_class ("BudgetExceededError", "ProxyRateLimitError",
//     "KeyNotFoundError").
//
//   - error.code (keyword) -- "Error code describing the error." Carries
//     the gateway's own error_code string.
//
// Only error.message is populated from the content plane; type and code
// come from the gateway plane alone. Langfuse carries neither -- deriving
// a class by string-matching "Budget has been exceeded!" would be exactly
// the plausible-but-invented field this project refuses to emit.
//
// error.type is load-bearing rather than decorative, and there is a
// concrete reason: a budget block and a rate limit are BOTH HTTP 429.
// Verified on live traffic -- BudgetExceededError and ProxyRateLimitError
// carry error_code "429" alike. A detection that groups enforcement by
// status code cannot tell "this key is out of money" from "this key is
// going too fast", which are different incidents with different
// responses. error.type is the only field that separates them.
//
// Pointer so a document for a request that did not fail carries no error
// object at all, rather than an empty one that a query for "does error
// exist" would match.
type ecsError struct {
	Message string `json:"message,omitempty"`
	Type    string `json:"type,omitempty"`
	Code    string `json:"code,omitempty"`
}

type idField struct {
	ID string `json:"id"`
}

type ecsMeta struct {
	Version string `json:"version"`
}

// event holds ECS core event.* fields. Verified against Elastic's ECS
// "event" field group reference (elastic.co/docs/reference/ecs/ecs-event)
// on 2026-07-29:
//   - event.kind (keyword) -- "event" is a documented allowed value.
//   - event.category (keyword, array) -- "api" is a documented allowed
//     value; chosen because ECS describes it as covering "interaction with
//     a REST-ish API," which an LLM chat-completion call is.
//   - event.dataset, event.module (keyword)
//   - event.duration (long) -- nanoseconds.
//   - event.ingested (date)
//   - event.reference (keyword) -- "Reference URL linking to additional
//     information about this event"; used here to carry the Langfuse UI
//     link (see model.LLMEvent.SourceRef), so an analyst can click
//     straight from a Kibana alert back into Langfuse's own trace view.
//   - event.outcome (keyword) -- one of ECS's four categorization fields.
//     Allowed values are exactly "success", "failure", "unknown"
//     (verified 2026-07-31); model.Status is defined to those three
//     strings so this is a direct assignment rather than a translation.
//     Omitted entirely when the source gave no basis to decide, which is
//     why this is omitempty and model.StatusUnknown is the empty string:
//     an absent outcome and an explicit "unknown" would otherwise be two
//     spellings of the same non-answer.
//   - event.type (keyword, array) -- one of ECS's four categorization
//     fields. "allowed" and "denied" are both documented allowed values
//     (verified 2026-08-01) and are expected types for the "api"
//     category; "start" is an expected type for the "authentication"
//     category, which is why an auth failure carries both.
//   - event.action (keyword) -- "The action captured by the event... more
//     specific than event.category." Free-form by design; this project
//     uses a small closed vocabulary (see gatewayAction).
//   - event.start / event.end (date) -- the request's own boundaries.
//     These exist separately from @timestamp because the two datasets
//     timestamp different instants: the gateway records request start,
//     while Langfuse records when its callback fired (after the response
//     on a success, near the start on a refusal). event.start means the
//     same instant on both planes -- measured agreement is
//     sub-millisecond -- and is therefore what cross-plane correlation
//     compares. See docs/CORRELATION.md §5.
type event struct {
	Kind      string   `json:"kind"`
	Category  []string `json:"category,omitempty"`
	Type      []string `json:"type,omitempty"`
	Action    string   `json:"action,omitempty"`
	Dataset   string   `json:"dataset"`
	Module    string   `json:"module"`
	Outcome   string   `json:"outcome,omitempty"`
	Start     string   `json:"start,omitempty"`
	End       string   `json:"end,omitempty"`
	Duration  *int64   `json:"duration,omitempty"`
	Ingested  string   `json:"ingested,omitempty"`
	Reference string   `json:"reference,omitempty"`
}

// labels carries wiretap's own ground-truth scenario labels, quarantined
// under labels.* specifically so nothing resembling a field a detection
// rule would naturally query (llm.*, gen_ai.*, tags) can be confused with
// it. See notes.md: an outcome label is how a detection gets graded, never
// something a detection is allowed to key on.
type labels struct {
	WiretapOutcome  string `json:"wiretap_outcome,omitempty"`
	WiretapScenario string `json:"wiretap_scenario,omitempty"`
}
