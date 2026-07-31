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
	Error     *ecsError `json:"error,omitempty"`
	LLM       llm       `json:"llm"`
	Labels    labels    `json:"labels"`
	Tags      []string  `json:"tags,omitempty"`
}

// ecsError holds ECS core error.* fields. Verified against Elastic's ECS
// "error" field group reference (elastic.co/docs/reference/ecs/ecs-error)
// on 2026-07-31:
//   - error.message (match_only_text) -- "Error message." Carries the
//     source's own explanation of why a request failed; for this
//     project's Langfuse data that is an ERROR observation's
//     statusMessage, which is LiteLLM's enforcement text verbatim.
//
// Only error.message is populated from the content plane. error.type
// (the exception class) and error.code exist in ECS and map cleanly to
// LiteLLM's structured error_information, but Langfuse carries neither --
// classifying "Budget has been exceeded!" into a class would mean string
// matching on a human-readable message, which is exactly the kind of
// plausible-but-invented field this project refuses to emit. The gateway
// plane reports both as structured data; that is one of the things it is
// for, and where they will come from.
//
// Pointer so a document for a request that did not fail carries no error
// object at all, rather than an empty one that a query for "does error
// exist" would match.
type ecsError struct {
	Message string `json:"message,omitempty"`
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
type event struct {
	Kind      string   `json:"kind"`
	Category  []string `json:"category,omitempty"`
	Dataset   string   `json:"dataset"`
	Module    string   `json:"module"`
	Outcome   string   `json:"outcome,omitempty"`
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
