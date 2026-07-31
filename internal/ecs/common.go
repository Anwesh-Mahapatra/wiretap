package ecs

import (
	"time"

	"wiretap/internal/model"
)

// newDocument builds the fields every dataset shares, from the facts every
// source reports. It exists so @timestamp, ecs.version, trace.id,
// event.start/end and the rest are constructed in exactly one place rather
// than once per mapper -- two mappers each formatting a timestamp their own
// way is how two datasets end up subtly non-comparable, and a correlation
// query that compares them is the thing this whole module is for.
//
// It deliberately does NOT set anything a source might not know:
// event.outcome comes from ev.Status (absent when unknown), and
// event.type/event.action are left to the per-source mapper because
// deciding a request was *denied* rather than merely failed requires the
// error class, which only the gateway has.
func newDocument(ev *model.LLMEvent, dataset string) *Document {
	doc := &Document{
		ECS: ecsMeta{Version: ECSVersion},
		Event: event{
			Kind:     "event",
			Category: []string{categoryAPI},
			Dataset:  dataset,
			Module:   "wiretap",
			Outcome:  string(ev.Status),
		},
		Labels: labels{
			WiretapOutcome:  string(ev.Outcome),
			WiretapScenario: ev.TraceName,
		},
		Tags: ev.Tags,
	}

	if !ev.RequestTimestamp.IsZero() {
		doc.Timestamp = formatTime(ev.RequestTimestamp)
	}
	// event.start / event.end are the request's own boundaries and mean the
	// same instant on both planes, unlike @timestamp. See event's doc
	// comment and docs/CORRELATION.md §5.
	if !ev.StartTime.IsZero() {
		doc.Event.Start = formatTime(ev.StartTime)
	}
	if !ev.EndTime.IsZero() {
		doc.Event.End = formatTime(ev.EndTime)
	}
	if !ev.IngestTimestamp.IsZero() {
		doc.Event.Ingested = formatTime(ev.IngestTimestamp)
	}
	if ev.Duration != nil {
		ns := ev.Duration.Nanoseconds()
		doc.Event.Duration = &ns
	}

	if ev.TraceID != "" {
		doc.Trace = &idField{ID: ev.TraceID}
	}
	if ev.SessionID != "" {
		doc.Session = &idField{ID: ev.SessionID}
	}
	if ev.UserID != "" {
		doc.User = &idField{ID: ev.UserID}
	}

	if ev.StatusMessage != "" {
		doc.Error = &ecsError{Message: ev.StatusMessage}
	}

	return doc
}

// Datasets. Both planes live behind one index pattern and are told apart by
// event.dataset, so these two strings are what every cross-plane query
// filters on. See docs/CORRELATION.md §3.
const (
	DatasetLangfuse = "wiretap.langfuse"
	DatasetLiteLLM  = "wiretap.litellm"
)

// ECS event.category allowed values used by this project. Verified against
// Elastic's ECS event.category allowed-values reference on 2026-08-01.
//
// categoryAPI applies to every document this project produces: ECS
// describes it as annotating "API calls that occured on a system", and its
// expected event types include allowed, denied, access and info.
//
// categoryAuthentication applies only to events "related to the challenge
// and response process in which credentials are supplied and verified".
// An auth failure at the gateway is exactly that, and it is *also* an API
// call -- ECS defines event.category as an array precisely so an event can
// be both. Its expected event types are start, end and info, which is why
// an auth failure carries typeStart alongside typeDenied rather than
// claiming a category whose vocabulary it then ignores.
const (
	categoryAPI            = "api"
	categoryAuthentication = "authentication"
)

// ECS event.type allowed values used by this project. Verified against
// Elastic's ECS event.type allowed-values reference on 2026-08-01:
// "allowed", "denied" and "start" are all documented values.
const (
	typeAllowed = "allowed"
	typeDenied  = "denied"
	typeStart   = "start"
)

// formatTime renders a timestamp the one way every dataset renders it.
// Sharing this is not fussiness: Elasticsearch's date parsing is lenient
// enough that two mappers formatting differently would both index fine and
// only diverge under a range query, which is the least visible place for a
// bug to live.
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}
