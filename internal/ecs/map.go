package ecs

import (
	"encoding/json"
	"strings"

	"wiretap/internal/model"
)

// Config carries the small amount of context the mappers need beyond the
// event itself. It exists so Map stays a pure function -- everything it
// needs (including "what time is it") is a parameter, not something it
// reaches out and reads for itself.
type Config struct {
	// LangfuseBaseURL is prepended to ev.SourceRef (a path like
	// "/project/x/traces/y") to build event.reference as a full,
	// click-from-Kibana URL. If ev.SourceRef is already absolute (starts
	// with http:// or https://), this is ignored. Empty means "no base
	// configured" -- event.reference falls back to the bare path, which is
	// still more useful than nothing.
	LangfuseBaseURL string

	// GenAISystemFallback is what gen_ai.system falls back to when neither
	// a gateway-reported provider nor a model-name route prefix
	// identifies one.
	//
	// It used to be named GenAISystem and was used unconditionally, which
	// meant every document claimed "groq" whether or not Groq served it --
	// correct only while config.yaml had exactly one model_list entry, and
	// a confident lie the day it had two. The rename is deliberate: a
	// field called GenAISystem invites being used as the answer, and a
	// field called GenAISystemFallback does not. See provider.go.
	GenAISystemFallback string

	// GenAIOperationFallback is used when the source reports nothing to
	// derive an operation from. On the content plane that is always,
	// because Langfuse types every call as a GENERATION and records no
	// distinction between chat and embeddings; on the gateway plane it
	// applies only to refused requests, which never got a call_type. See
	// DefaultGenAIOperation for why a constant is defensible here and not
	// for gen_ai.system.
	GenAIOperationFallback string
}

// DefaultConfig returns the Config for mapping this project's Langfuse
// content plane. Callers wanting different values build their own Config.
func DefaultConfig(langfuseBaseURL string) Config {
	return Config{
		LangfuseBaseURL:        langfuseBaseURL,
		GenAISystemFallback:    DefaultGenAISystem,
		GenAIOperationFallback: DefaultGenAIOperation,
	}
}

// Map builds an ECS Document for the *content* plane (event.dataset
// "wiretap.langfuse") from ev. It is a pure function: no I/O, no globals,
// no clock reads -- every value in the result traces back to either ev or
// cfg, both supplied by the caller, which is what makes a byte-stable
// golden-file test possible at all. event.ingested in particular comes
// from ev.IngestTimestamp (Langfuse's own createdAt), not from "now": Map
// has no clock to read from, on purpose.
//
// Fields deliberately NOT set here, and why:
//
//   - event.type. Deciding a request was *denied* rather than merely
//     failed needs the error class, and the content plane has only a
//     sentence of English. Claiming "denied" for an upstream provider
//     error would be an invented fact; see MapGateway, which has the
//     structured class and can say it honestly.
//   - http.*, error.type, error.code, llm.key.*. The content plane has no
//     access to any of them.
func Map(ev *model.LLMEvent, cfg Config) *Document {
	doc := newDocument(ev, DatasetLangfuse)

	doc.LLM = llm{
		llmContent: &llmContent{
			SystemPrompt:           lastMessageContent(ev.Messages, "system"),
			UserPrompt:             lastMessageContent(ev.Messages, "user"),
			Output:                 ev.OutputContent,
			OutputRole:             ev.OutputRole,
			Messages:               encodeMessages(ev.Messages),
			MessageCount:           len(ev.Messages),
			OutputLength:           len(ev.OutputContent),
			GenerationCount:        ev.GenerationCount,
			ErroredGenerationCount: ev.ErroredGenerationCount,
		},
		TotalCostUSD: ev.TotalCost,
	}

	if ev.SourceRef != "" {
		doc.Event.Reference = buildReference(cfg.LangfuseBaseURL, ev.SourceRef)
	}
	if ev.UserID != "" {
		doc.Related = &related{User: []string{ev.UserID}}
	}

	doc.GenAI = buildGenAI(ev, cfg)

	return doc
}

func buildGenAI(ev *model.LLMEvent, cfg Config) *genAI {
	// Provider is derived from the best evidence on the event, falling
	// back to the configured constant only when nothing identifies one.
	// The gateway's own provider field is preferred over a model-name
	// prefix; both are preferred over the fallback. See provider.go.
	var gatewayProvider, callType string
	if ev.Gateway != nil {
		gatewayProvider = ev.Gateway.Provider
		callType = ev.Gateway.CallType
	}
	system, _ := deriveGenAISystem(gatewayProvider, ev.ResponseModel, ev.RequestModel, cfg.GenAISystemFallback)

	g := &genAI{System: system}
	if op := deriveOperation(callType, cfg.GenAIOperationFallback); op != "" {
		g.Operation = &genAIOperation{Name: op}
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
