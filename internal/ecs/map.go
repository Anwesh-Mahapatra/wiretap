package ecs

import (
	"encoding/json"
	"strings"
	"time"

	"wiretap/internal/model"
)

// Config carries the small amount of context Map needs beyond the event
// itself. It exists so Map stays a pure function -- everything it needs
// (including "what time is it") is a parameter, not something it reaches
// out and reads for itself.
type Config struct {
	// LangfuseBaseURL is prepended to ev.SourceRef (a path like
	// "/project/x/traces/y") to build event.reference as a full,
	// click-from-Kibana URL. If ev.SourceRef is already absolute (starts
	// with http:// or https://), this is ignored. Empty means "no base
	// configured" -- event.reference falls back to the bare path, which is
	// still more useful than nothing.
	LangfuseBaseURL string
	// GenAISystem and GenAIOperationName are this deployment's constant
	// answers to "which Gen AI product served this" and "what kind of
	// call was this" (see genai.go's doc comment on gen_ai.system for why
	// "groq" is a real, spec-recognised value here, not a placeholder).
	// They're threaded through Config rather than hardcoded in Map so a
	// future multi-provider deployment doesn't require editing the
	// mapper, and so golden tests can pin them explicitly.
	GenAISystem        string
	GenAIOperationName string
}

// DefaultConfig returns the Config matching this project's actual, current
// deployment (see config.yaml: LiteLLM proxies every request to Groq's
// llama-3.3-70b-versatile). Callers that want different values (a
// different provider, a different Langfuse base URL) build their own
// Config instead of calling this.
func DefaultConfig(langfuseBaseURL string) Config {
	return Config{
		LangfuseBaseURL:    langfuseBaseURL,
		GenAISystem:        "groq",
		GenAIOperationName: "chat",
	}
}

// Map builds an ECS Document from ev. It is a pure function: no I/O, no
// globals, no clock reads -- every value in the result traces back to
// either ev or cfg, both supplied by the caller, which is what makes a
// byte-stable golden-file test possible at all. event.ingested in
// particular comes from ev.IngestTimestamp (Langfuse's own createdAt --
// confirmed present on real captured data despite its absence from
// Langfuse's published OpenAPI spec, see internal/parse's package doc),
// not from "now": Map has no clock to read from, on purpose.
func Map(ev *model.LLMEvent, cfg Config) *Document {
	doc := &Document{
		ECS: ecsMeta{Version: ECSVersion},
		Event: event{
			Kind:     "event",
			Category: []string{"api"},
			Dataset:  "wiretap.langfuse",
			Module:   "wiretap",
		},
		LLM: llm{
			SystemPrompt:    lastMessageContent(ev.Messages, "system"),
			UserPrompt:      lastMessageContent(ev.Messages, "user"),
			Output:          ev.OutputContent,
			OutputRole:      ev.OutputRole,
			Messages:        encodeMessages(ev.Messages),
			MessageCount:    len(ev.Messages),
			OutputLength:    len(ev.OutputContent),
			TotalCostUSD:    ev.TotalCost,
			GenerationCount: ev.GenerationCount,
		},
		Labels: labels{
			WiretapOutcome:  string(ev.Outcome),
			WiretapScenario: ev.TraceName,
		},
		Tags: ev.Tags,
	}

	if !ev.RequestTimestamp.IsZero() {
		doc.Timestamp = ev.RequestTimestamp.UTC().Format(time.RFC3339Nano)
	}
	if !ev.IngestTimestamp.IsZero() {
		doc.Event.Ingested = ev.IngestTimestamp.UTC().Format(time.RFC3339Nano)
	}
	if ev.Duration != nil {
		ns := ev.Duration.Nanoseconds()
		doc.Event.Duration = &ns
	}
	if ev.SourceRef != "" {
		doc.Event.Reference = buildReference(cfg.LangfuseBaseURL, ev.SourceRef)
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

	doc.GenAI = buildGenAI(ev, cfg)

	return doc
}

func buildGenAI(ev *model.LLMEvent, cfg Config) *genAI {
	g := &genAI{System: cfg.GenAISystem}
	if cfg.GenAIOperationName != "" {
		g.Operation = &genAIOperation{Name: cfg.GenAIOperationName}
	}
	if ev.RequestModel != "" || ev.MaxTokens != nil {
		g.Request = &genAIRequest{Model: ev.RequestModel, MaxTokens: ev.MaxTokens}
	}
	if ev.ResponseModel != "" || ev.ResponseID != "" {
		g.Response = &genAIResponse{Model: ev.ResponseModel, ID: ev.ResponseID}
	}
	if ev.InputTokens != nil || ev.OutputTokens != nil {
		g.Usage = &genAIUsage{InputTokens: ev.InputTokens, OutputTokens: ev.OutputTokens}
	}
	if g.System == "" && g.Operation == nil && g.Request == nil && g.Response == nil && g.Usage == nil {
		return nil
	}
	return g
}

// lastMessageContent returns the content of the last message with the
// given role, or "" if there is none -- last, not first, because the
// current turn is what a detection cares about in a multi-turn
// conversation (see llm.go's UserPrompt doc comment).
func lastMessageContent(msgs []model.Message, role string) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == role {
			return msgs[i].Content
		}
	}
	return ""
}

func encodeMessages(msgs []model.Message) string {
	if len(msgs) == 0 {
		return ""
	}
	out := make([]llmMessage, len(msgs))
	for i, m := range msgs {
		out[i] = llmMessage{Role: m.Role, Content: m.Content}
	}
	// []llmMessage of plain strings cannot fail to marshal.
	b, _ := json.Marshal(out)
	return string(b)
}

func buildReference(baseURL, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	if baseURL == "" {
		return ref
	}
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(ref, "/")
}
