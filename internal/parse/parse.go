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
//   - model.LLMEvent.Temperature and FinishReasons are always left unset
//     for this source -- confirmed genuinely absent from Langfuse's
//     response by direct inspection (captured a live GET
//     /api/public/traces/{id} response and grepped it for every plausible
//     location; nothing). Guessing at an undocumented key to fill them
//     would violate the same "don't invent a field" rule that applies to
//     picking ECS names; leaving them unset is the honest answer.
//
// RequestModel, MaxTokens, ResponseModel, ResponseID, InputTokens, and
// OutputTokens *are* recoverable, but only when a line's "observations"
// field is full objects rather than bare ID strings -- see
// decodeObservations. As of internal/pipeline's fetch enrichment, new
// archive lines are always full objects; older, unenriched archives (or
// tracepump/wiretapd run with enrichment off) still parse fine, just
// without these fields, exactly as before enrichment existed.
//
// RequestModel and ResponseID specifically come from places that are
// LiteLLM/Langfuse-integration conventions, not documented Langfuse
// fields -- see wireObservationMetadata and completionID's doc comments.
package parse

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"wiretap/internal/model"
)

// healthCheckTag marks the traffic LiteLLM generates for its own model
// health checks. Kept in sync with cmd/tracepump's constant of the same
// name and meaning.
//
// One literal, both planes. LiteLLM defines it once
// (LITTELM_INTERNAL_HEALTH_SERVICE_ACCOUNT_NAME in litellm/constants.py)
// and stamps it onto a health check twice over -- as a request tag, which
// is what reaches Langfuse as a trace tag, and as the identity of the
// synthetic service account the call is billed to, which is what reaches
// the spend row. So the content plane matching a trace tag and the gateway
// plane matching a spend record are matching the same fact from the same
// source, not two conventions that happen to agree.
//
// The two planes deliberately match different stamps, though, because the
// stamps are not equally trustworthy: a request tag is caller-supplied and
// the service account is not. A Langfuse trace carries only the tag, so
// this plane has no choice; the gateway plane does, and takes the other
// one. See isGatewayHealthCheck, and docs/DETECTIONS.md for the gap that
// leaves on this side.
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
// needs: enough to find every generation that answered and read each
// one's model, token usage, requested model, and max_tokens.
type wireObservation struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
	// Model means different things depending on Level, and this is not a
	// Langfuse subtlety but a LiteLLM one, confirmed against real captured
	// data: on a non-ERROR observation it is the model that *answered*,
	// provider-prefixed ("groq/llama-3.3-70b-versatile"); on an ERROR
	// observation nothing answered, so it is the model the caller
	// *requested*, unprefixed ("llama-3.3-70b-versatile"). applyGenerations
	// routes it to ResponseModel or RequestModel accordingly -- mapping it
	// unconditionally to ResponseModel would claim a model served a request
	// it rejected.
	Model string `json:"model"`
	// Level is Langfuse's per-observation severity: "DEFAULT", "DEBUG",
	// "WARNING", or "ERROR". This project's LiteLLM integration sets ERROR
	// on every observation for a request the proxy refused (budget block,
	// auth failure) via config.yaml's failure_callback -- so ERROR is how
	// the *content* plane sees an enforcement action at all.
	Level string `json:"level"`
	// StatusMessage is the source's own explanation, populated alongside
	// an ERROR level. For this deployment it is LiteLLM's enforcement text
	// verbatim, e.g. "Budget has been exceeded! Key=bob (sk-...9SfA) ...".
	// Note it already contains only LiteLLM's own truncated key suffix,
	// never a usable credential.
	StatusMessage string `json:"statusMessage"`
	// StartTime is when this generation began, and it is the ONLY
	// trustworthy way to order a trace's observations. Langfuse does not
	// return them in chronological order -- see orderedGenerations.
	//
	// It is also the content plane's only accurate record of when the
	// request actually started: the trace-level timestamp is when
	// LiteLLM's callback fired, which is after the response on a success.
	// Measured against the gateway's own startTime for the same request,
	// observation startTime agrees to the millisecond -- both come from
	// the same process watching the same request -- which is what makes
	// event.start comparable across planes. See docs/CORRELATION.md §5.
	StartTime       string                     `json:"startTime"`
	EndTime         string                     `json:"endTime"`
	Usage           *wireUsage                 `json:"usage"`
	Latency         *float64                   `json:"latency"`
	Metadata        wireObservationMetadata    `json:"metadata"`
	ModelParameters wireObservationModelParams `json:"modelParameters"`
}

// observationLevelError is the Langfuse observation level this project's
// LiteLLM integration uses for a request the proxy refused.
const observationLevelError = "ERROR"

// wireObservationMetadata is the subset of an observation's metadata this
// parser reads. The real object is a large LiteLLM-internal blob --
// auth/budget/routing plumbing, dozens of fields -- with no Langfuse
// meaning of its own; only ModelGroup is modeled. This mirrors
// internal/langfuse.ObservationMetadata, duplicated rather than imported
// because internal/parse deliberately doesn't depend on internal/langfuse
// -- it decodes raw archive bytes, not typed API responses (see the
// package doc) -- the same reason healthCheckTag is its own constant here
// instead of an import.
type wireObservationMetadata struct {
	// ModelGroup is the model the *caller* requested, as distinct from
	// Model above, the model that actually answered. Confirmed present
	// and consistently different from Model across every trace this
	// project has captured (see internal/langfuse.ObservationMetadata's
	// doc comment for the full evidence). A LiteLLM convention, not a
	// documented Langfuse concept.
	ModelGroup string `json:"model_group"`
}

// wireObservationModelParams mirrors internal/langfuse.ObservationModelParameters --
// only MaxTokens is modeled, for the same "nothing else downstream reads
// the rest" reason given there.
type wireObservationModelParams struct {
	MaxTokens *int `json:"max_tokens"`
}

// completionID extracts the provider's completion ID (e.g.
// "chatcmpl-da63253c-...") from an observation's own ID, constructed by
// this project's Langfuse integration as
// "time-<HHMMSS-ffffff>_<completionID>". Mirrors
// internal/langfuse.Observation.CompletionID -- see that method's doc
// comment for why this is a function over a naming convention rather than
// a struct tag, and why it's duplicated here instead of shared (same
// reason as wireObservationMetadata).
func completionID(observationID string) (id string, ok bool) {
	_, after, found := strings.Cut(observationID, "_")
	if !found || after == "" {
		return "", false
	}
	return after, true
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
		applyGenerations(ev, obs)
	}

	return ev, nil
}

// applyGenerations reduces every GENERATION observation in obs onto ev.
// Other observation types (SPAN, EVENT, ...) carry no usage and are
// ignored -- a trace's non-generation observations are bookkeeping, not
// something a token-spike or cost detection cares about.
//
// A trace can carry more than one GENERATION observation (a multi-turn
// exchange, or a retried call). Two different reductions are used,
// deliberately not the same one:
//
//   - Token counts are summed. A trace's real cost to answer is the total
//     across every call it took, not just one of them -- a per-user
//     spike detection (see docs/DETECTIONS.md) that silently read only
//     one generation would under-report exactly the abuse it exists to
//     catch.
//   - Model, request max_tokens, and response/completion ID are
//     single-valued fields, so they take the *last* generation, not the
//     first. In a multi-turn or retried exchange, the final generation is
//     the one that actually produced the output already mapped to
//     llm.output (see internal/ecs). Taking the first would pair that
//     completion with a different call's metadata -- a narrower repeat of
//     the trace-merge bug this project already fixed once (see
//     notes.md): syntactically valid, semantically mismatched data.
//
// GenerationCount records how many GENERATION observations contributed,
// so a summed token count is never presented without the context of how
// many calls it summarizes.
//
// Token counts are only set when *every* GENERATION observation reported
// usage. A trace with, say, two generations where only one has a usage
// block is a real, observed shape (a call that errored before Langfuse
// recorded its usage) -- summing just the one that has data would produce
// a number that looks like the trace's total cost but silently
// undercounts it, which is worse than reporting nothing: it's exactly the
// syntactically-valid-but-semantically-false telemetry notes.md already
// documents one incident of. Partial data here stays absent, not partial.
//
// ERROR-level generations get three specific, narrow treatments, because a
// request the proxy refused is not a request that ran and cost nothing:
//
//   - Their Model feeds RequestModel, never ResponseModel. Nothing
//     answered, so there is no answering model to report; what LiteLLM
//     puts there is the model the caller asked for.
//   - Their StatusMessage is carried onto the event, and Status becomes
//     failure when *no* generation succeeded.
//   - They are excluded from GenerationCount and from token summation
//     entirely, and counted separately in ErroredGenerationCount. A
//     refused attempt is not a call the model answered, so it must not
//     inflate the count that exists to say how many answers a token sum
//     summarizes. Langfuse itself agrees: a mixed trace's own
//     trace-level totalCost equals the sum of the non-ERROR observations
//     alone (verified on real data, 2026-07-31), so counting them here
//     would put wiretap at odds with its own source.
//   - When no generation succeeded, token counts and cost are left
//     genuinely absent rather than the zeros Langfuse reports. Langfuse
//     really does send usage {input:0, output:0} and calculatedTotalCost 0
//     on a blocked request, and taking those literally is how a blocked
//     request came to index as "a successful request that used no tokens
//     and cost nothing" -- valid fields, plausible values, wrong answer.
//     Zero is what the source said; absent is what it meant.
func applyGenerations(ev *model.LLMEvent, obs []wireObservation) {
	var inputSum, outputSum int
	var succeeded, succeededWithUsage, errored int

	for _, g := range orderedGenerations(obs) {
		if g.Level == observationLevelError {
			errored++
			if ev.StatusMessage == "" && g.StatusMessage != "" {
				// Chronologically-first message wins: every attempt of a
				// blocked request reports the same enforcement text, and
				// the first one is the reason the request failed. Later
				// ones are repeats, not extra information. This is only
				// meaningfully "first" because orderedGenerations sorted
				// them; in array order it was whichever Langfuse listed
				// first.
				ev.StatusMessage = g.StatusMessage
			}
			// An ERROR observation still tells us which model the caller
			// asked for -- nothing answered, so LiteLLM puts the
			// requested model in the Model field. Everything else about
			// it (usage, cost, completion ID) describes a call that
			// never happened.
			if g.Model != "" && ev.ResponseModel == "" {
				ev.RequestModel = g.Model
			}
			if g.Metadata.ModelGroup != "" {
				ev.RequestModel = g.Metadata.ModelGroup
			}
			if g.ModelParameters.MaxTokens != nil {
				mt := *g.ModelParameters.MaxTokens
				ev.MaxTokens = &mt
			}
			continue
		}

		succeeded++
		if g.Usage != nil {
			inputSum += g.Usage.Input
			outputSum += g.Usage.Output
			succeededWithUsage++
		}

		// Last-generation-wins, over the chronologically sorted sequence:
		// later iterations simply overwrite these, so after the loop each
		// holds the value from the generation that genuinely ran last.
		if g.Model != "" {
			ev.ResponseModel = g.Model
		}
		if g.Metadata.ModelGroup != "" {
			ev.RequestModel = g.Metadata.ModelGroup
		}
		if g.ModelParameters.MaxTokens != nil {
			mt := *g.ModelParameters.MaxTokens
			ev.MaxTokens = &mt
		}
		if id, ok := completionID(g.ID); ok {
			ev.ResponseID = id
		}
	}

	ev.GenerationCount = succeeded
	ev.ErroredGenerationCount = errored
	applyObservationBounds(ev, obs)

	switch {
	case succeeded > 0:
		ev.Status = model.StatusSuccess
	case errored > 0:
		ev.Status = model.StatusFailure
	default:
		// No GENERATION observations at all. Nothing was observed to
		// succeed or fail, which is not the same as failing.
		ev.Status = model.StatusUnknown
	}

	if ev.Status == model.StatusFailure {
		// Nothing ran. Whatever zeros the source reported for usage and
		// cost describe an absence, not a measurement -- see this
		// function's doc comment.
		ev.InputTokens = nil
		ev.OutputTokens = nil
		ev.TotalCost = nil
		return
	}

	if succeeded > 0 && succeededWithUsage == succeeded {
		ev.InputTokens = &inputSum
		ev.OutputTokens = &outputSum
	}
}

// applyObservationBounds sets ev.StartTime and ev.EndTime from the widest
// span the trace's observations cover: the earliest start and the latest
// end, across every observation including ERROR ones.
//
// ERROR observations are included here even though they are excluded from
// counts and token sums, and the distinction is deliberate. A refused
// attempt did not produce a generation, so it must not inflate
// generation_count -- but it did happen, at a real instant, and it is part
// of how long this request occupied the system. For a fully-refused trace
// the ERROR observations are the *only* record of when anything happened,
// so excluding them would leave event.start empty on exactly the events
// the gateway plane exists to correlate.
//
// These are the content plane's contribution to cross-plane correlation.
// The trace-level timestamp cannot serve: it records when LiteLLM's
// callback fired, which trails the request by its full duration on a
// success. Observation startTime matches the gateway's startTime to the
// millisecond. See docs/CORRELATION.md §5.
func applyObservationBounds(ev *model.LLMEvent, obs []wireObservation) {
	for i := range obs {
		if t := parseObservationTime(obs[i].StartTime); !t.IsZero() {
			if ev.StartTime.IsZero() || t.Before(ev.StartTime) {
				ev.StartTime = t
			}
		}
		if t := parseObservationTime(obs[i].EndTime); !t.IsZero() {
			if ev.EndTime.IsZero() || t.After(ev.EndTime) {
				ev.EndTime = t
			}
		}
	}
}

func parseObservationTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// orderedGenerations returns obs's GENERATION observations sorted oldest
// first by startTime.
//
// This exists because **Langfuse's observations array is not in
// chronological order**, which is not documented anywhere and was invisible
// for as long as every captured trace had exactly one generation. Verified
// on a deliberately constructed mixed trace (see
// testdata/mixed_error_and_success.json): the generation starting at
// 10:43:12.078 is listed *before* two that started at 10:43:11.033.
//
// Everything in applyGenerations that says "last wins" means last in time,
// and said so in its comments long before it was true. Array position was
// standing in for chronology, and it silently is not the same thing.
//
// Observations whose startTime is missing or unparseable sort first, in
// their original relative order. Sorting them last would let an
// unorderable observation win the last-wins rule over one that can be
// placed in time -- exactly backwards. Real Langfuse data always carries
// startTime; this is the degradation path, and it keeps a fixture with no
// timestamps at all resolving by array order, as it did before.
func orderedGenerations(obs []wireObservation) []wireObservation {
	type timed struct {
		obs     wireObservation
		at      time.Time
		ordered bool
	}

	gens := make([]timed, 0, len(obs))
	for _, o := range obs {
		if o.Type != "GENERATION" {
			continue
		}
		t := timed{obs: o}
		if o.StartTime != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, o.StartTime); err == nil {
				t.at, t.ordered = parsed, true
			}
		}
		gens = append(gens, t)
	}

	sort.SliceStable(gens, func(i, j int) bool {
		if gens[i].ordered != gens[j].ordered {
			return !gens[i].ordered // unorderable first
		}
		if !gens[i].ordered {
			return false // both unorderable: SliceStable keeps array order
		}
		return gens[i].at.Before(gens[j].at)
	})

	out := make([]wireObservation, len(gens))
	for i, g := range gens {
		out[i] = g.obs
	}
	return out
}

// decodeObservations handles the polymorphism of Langfuse's "observations"
// field: the trace-list endpoint (what tracepump archives) returns an
// array of ID strings; the trace-detail endpoint returns full objects.
// full reports which shape raw actually contained. When full is false, obs
// is always empty -- there's nothing more to extract from bare ID strings,
// so callers should treat token counts and the answering model as unknown
// rather than absent-and-zero.
func decodeObservations(raw json.RawMessage) (obs []wireObservation, full bool) {
	if !jsonPresent(raw) {
		return nil, false
	}
	if err := json.Unmarshal(raw, &obs); err == nil {
		return obs, true
	}
	// Elements didn't decode as objects -- the list endpoint's shape, an
	// array of bare ID strings. Nothing further to extract.
	return nil, false
}

// decodeMessages best-effort-extracts an ordered message list from a
// trace's "input" field. Unrecognised shapes (or a genuinely absent input)
// yield no messages, not an error.
func decodeMessages(raw json.RawMessage) []model.Message {
	if !jsonPresent(raw) {
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
	if !jsonPresent(raw) {
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
