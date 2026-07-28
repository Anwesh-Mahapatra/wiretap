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
	Timestamp string   `json:"@timestamp,omitempty"`
	ECS       ecsMeta  `json:"ecs"`
	Event     event    `json:"event"`
	Trace     *idField `json:"trace,omitempty"`
	Session   *idField `json:"session,omitempty"`
	User      *idField `json:"user,omitempty"`
	GenAI     *genAI   `json:"gen_ai,omitempty"`
	LLM       llm      `json:"llm"`
	Labels    labels   `json:"labels"`
	Tags      []string `json:"tags,omitempty"`
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
type event struct {
	Kind      string   `json:"kind"`
	Category  []string `json:"category,omitempty"`
	Dataset   string   `json:"dataset"`
	Module    string   `json:"module"`
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
