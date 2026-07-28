// Package parse converts one raw NDJSON line from tracepump's Langfuse
// archive -- a trace exactly as Langfuse's public API returned it -- into a
// model.LLMEvent (see internal/model). It is the only package that needs to
// know Langfuse's JSON shape; everything downstream (internal/ecs) reads
// only model.LLMEvent, never Langfuse's field names directly.
//
// The wire types below were checked twice: first against Langfuse's own
// published OpenAPI spec (cloud.langfuse.com/generated/api/openapi.yml,
// checked 2026-07-29), and then against this project's own real, captured
// archive data from its self-hosted Langfuse instance (docker.io/langfuse/
// langfuse:3) -- and the two disagreed. The published spec's Trace schema
// omits projectId/createdAt/updatedAt/externalId; this project's actual
// running instance returns all four on every trace. Real captured data
// wins over documentation here -- wireTrace decodes all four directly.
// (externalId is real too, but always null in this project's data and has
// no model.LLMEvent field to go in; it's left undecoded.)
//
// Two things that hold up under both checks, worth knowing before
// extending this package:
//
//   - ProjectID prefers the direct "projectId" field, falling back to a
//     best-effort parse of htmlPath's "/project/<id>/" segment only if
//     "projectId" is ever absent (e.g. an older Langfuse version) -- belt
//     and suspenders, not a primary source.
//   - model.LLMEvent.RequestModel, MaxTokens, Temperature, FinishReasons,
//     and ResponseID are always left unset for this source. LiteLLM's
//     Langfuse callback (the only producer of the data this project
//     ingests) records a simplified input/output shape -- not the raw
//     provider request/response objects -- so none of these are reliably
//     recoverable here. Guessing at an undocumented key to fill them would
//     violate the same "don't invent a field" rule that applies to
//     picking ECS names; leaving them unset is the honest answer.
//
// ResponseModel, InputTokens, and OutputTokens *are* recoverable, but only
// when a line's "observations" field is full objects rather than bare ID
// strings -- see decodeObservations.
package parse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"wiretap/internal/model"
)

// healthCheckTag marks traces LiteLLM generates for its own periodic model
// health checks. Kept in sync with cmd/tracepump's constant of the same
// name and meaning.
const healthCheckTag = "litellm-internal-health-check"

// scenarioNamePrefix is how main.go names every trace it produces (see
// metadata.trace_name in cmd/wiretap/main.go): "wiretap-<scenario>".
const scenarioNamePrefix = "wiretap-"

// wireTrace mirrors the fields Langfuse's public API actually returns for a
// trace object. See the package doc for what's deliberately absent from
// this list despite appearing in some Langfuse documentation.
type wireTrace struct {
	ID          string          `json:"id"`
	ProjectID   string          `json:"projectId"`
	Timestamp   string          `json:"timestamp"`
	Name        *string         `json:"name"`
	Input       json.RawMessage `json:"input"`
	Output      json.RawMessage `json:"output"`
	SessionID   *string         `json:"sessionId"`
	UserID      *string         `json:"userId"`
	Tags        []string        `json:"tags"`
	Environment string          `json:"environment"`
	HTMLPath    string          `json:"htmlPath"`
	Latency     *float64        `json:"latency"`
	TotalCost   *float64        `json:"totalCost"`
	CreatedAt   string          `json:"createdAt"`
	// Observations is polymorphic: the list endpoint (what tracepump
	// actually archives today) returns an array of ID strings; the detail
	// endpoint returns full objects. See decodeObservations.
	Observations json.RawMessage `json:"observations"`
}

// wireInputMessages is the shape this project's LiteLLM-to-Langfuse
// integration gives trace.input. Langfuse itself types input as arbitrary
// JSON -- this is an integration convention, not a Langfuse guarantee.
type wireInputMessages struct {
	Messages []wireMessage `json:"messages"`
}

type wireMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// wireOutput is the shape this project's integration gives trace.output.
type wireOutput struct {
	Content string `json:"content"`
	Role    string `json:"role"`
	// ToolCalls is decoded only so its presence never trips json.Unmarshal.
	// Tool-call support in model.LLMEvent is Module 8 work (see
	// internal/model's Message doc comment) -- it is deliberately not
	// mapped any further than this.
	ToolCalls json.RawMessage `json:"tool_calls"`
}

// wireUsage mirrors Langfuse's (deprecated but still populated) Usage
// object on a full observation.
type wireUsage struct {
	Input  int    `json:"input"`
	Output int    `json:"output"`
	Total  int    `json:"total"`
	Unit   string `json:"unit"`
}

// wireObservation is the subset of a full Observation object this parser
// needs: enough to find the generation that answered and read its model
// and token usage.
type wireObservation struct {
	ID      string     `json:"id"`
	Type    string     `json:"type"`
	Name    string     `json:"name"`
	Model   string     `json:"model"`
	Usage   *wireUsage `json:"usage"`
	Latency *float64   `json:"latency"`
}

// htmlPathProjectRe matches Langfuse's UI path convention,
// "/project/<id>/traces/<id>". Best-effort: if htmlPath doesn't match this
// shape, ProjectID is simply left empty rather than guessed at.
var htmlPathProjectRe = regexp.MustCompile(`/project/([^/]+)/`)

// ParseLine converts one NDJSON line -- one raw Langfuse trace, exactly as
// tracepump archived it -- into a model.LLMEvent. lineNo is used only for
// error reporting (see LineError). Returns a *LineError if the line isn't
// valid JSON, or doesn't even carry a trace ID; any other unrecognised or
// null sub-shape (input, output, observations, user/session ID) degrades to
// an empty/unset field on the result rather than failing the whole line --
// a trace with a strangely-shaped optional field is still mostly usable
// data, and it is the pipeline's later stages (not this one) that decide
// whether "mostly usable" is good enough.
func ParseLine(line []byte, lineNo int) (*model.LLMEvent, error) {
	var wt wireTrace
	if err := json.Unmarshal(line, &wt); err != nil {
		return nil, newLineError(lineNo, line, fmt.Errorf("decoding trace: %w", err))
	}
	if wt.ID == "" {
		return nil, newLineError(lineNo, line, fmt.Errorf("trace has no id"))
	}

	ev := &model.LLMEvent{
		TraceID:      wt.ID,
		ProjectID:    wt.ProjectID,
		Environment:  wt.Environment,
		Tags:         wt.Tags,
		TotalCost:    wt.TotalCost,
		Source:       model.SourceLangfuse,
		SourceRef:    wt.HTMLPath,
		SourceRecord: append([]byte(nil), line...),
	}
	if ev.ProjectID == "" {
		// Belt and suspenders: real data always has projectId directly,
		// but fall back to htmlPath's "/project/<id>/" segment rather
		// than leave this unset if a future/older Langfuse version ever
		// omits it.
		ev.ProjectID = projectIDFromHTMLPath(wt.HTMLPath)
	}

	if wt.Name != nil {
		ev.TraceName = *wt.Name
		ev.Outcome = deriveOutcome(*wt.Name)
	}
	if wt.SessionID != nil {
		ev.SessionID = *wt.SessionID
	}
	if wt.UserID != nil {
		ev.UserID = *wt.UserID
	}
	if wt.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339Nano, wt.Timestamp); err == nil {
			ev.RequestTimestamp = t
		}
	}
	if wt.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, wt.CreatedAt); err == nil {
			ev.IngestTimestamp = t
		}
	}
	if wt.Latency != nil {
		d := time.Duration(*wt.Latency * float64(time.Second))
		ev.Duration = &d
	}

	ev.IsHealthCheck = hasTag(wt.Tags, healthCheckTag)
	ev.Messages = decodeMessages(wt.Input)

	if out := decodeOutput(wt.Output); out != nil {
		ev.OutputContent = out.Content
		ev.OutputRole = out.Role
	}

	if obs, full := decodeObservations(wt.Observations); full {
		if g := firstGeneration(obs); g != nil {
			if g.Model != "" {
				ev.ResponseModel = g.Model
			}
			if g.Usage != nil {
				in, out := g.Usage.Input, g.Usage.Output
				ev.InputTokens = &in
				ev.OutputTokens = &out
			}
		}
	}

	return ev, nil
}

// decodeObservations handles the polymorphism of Langfuse's "observations"
// field: the trace-list endpoint (what tracepump archives) returns an
// array of ID strings; the trace-detail endpoint returns full objects.
// full reports which shape raw actually contained. When full is false, obs
// is always empty -- there's nothing more to extract from bare ID strings,
// so callers should treat token counts and the answering model as unknown
// rather than absent-and-zero.
func decodeObservations(raw json.RawMessage) (obs []wireObservation, full bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, false
	}
	if err := json.Unmarshal(raw, &obs); err == nil {
		return obs, true
	}
	// Elements didn't decode as objects -- the list endpoint's shape, an
	// array of bare ID strings. Nothing further to extract.
	return nil, false
}

func firstGeneration(obs []wireObservation) *wireObservation {
	for i := range obs {
		if obs[i].Type == "GENERATION" {
			return &obs[i]
		}
	}
	return nil
}

// decodeMessages best-effort-extracts an ordered message list from a
// trace's "input" field. Unrecognised shapes (or a genuinely absent input)
// yield no messages, not an error.
func decodeMessages(raw json.RawMessage) []model.Message {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var wrapped wireInputMessages
	if err := json.Unmarshal(raw, &wrapped); err == nil && wrapped.Messages != nil {
		return toModelMessages(wrapped.Messages)
	}
	var bare []wireMessage
	if err := json.Unmarshal(raw, &bare); err == nil {
		return toModelMessages(bare)
	}
	return nil
}

func toModelMessages(wm []wireMessage) []model.Message {
	if len(wm) == 0 {
		return nil
	}
	out := make([]model.Message, len(wm))
	for i, m := range wm {
		out[i] = model.Message{Role: m.Role, Content: m.Content}
	}
	return out
}

func decodeOutput(raw json.RawMessage) *wireOutput {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var out wireOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return &out
}

// deriveOutcome reads the scenario outcome off the trace name
// ("wiretap-injection" -> injection) rather than indexing into tags: the
// name is set explicitly and stably by cmd/wiretap (see main.go), while
// tags[2] being the outcome is an accident of today's tag ordering that
// breaks the moment LiteLLM or a scenario adds another auto-tag.
func deriveOutcome(name string) model.Outcome {
	if !strings.HasPrefix(name, scenarioNamePrefix) {
		return ""
	}
	switch strings.TrimPrefix(name, scenarioNamePrefix) {
	case string(model.OutcomeBenign):
		return model.OutcomeBenign
	case string(model.OutcomeInjection):
		return model.OutcomeInjection
	case string(model.OutcomeTruncated):
		return model.OutcomeTruncated
	default:
		return ""
	}
}

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

func projectIDFromHTMLPath(htmlPath string) string {
	m := htmlPathProjectRe.FindStringSubmatch(htmlPath)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}
