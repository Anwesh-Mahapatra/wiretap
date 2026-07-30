### Field Definitions & Detection Logic

* **`trace_id`**: Acts as a pivot or join key. It goes in YARA-L outcome variables, not the condition. It is emitted as evidence for investigations to reconstruct attack chains.


* **`user_id`**: Acts as the aggregation spine. It is mandatory for all behavioral detections, such as refusal rate, token rate, and payload diversity.


* **`session_id`**: Represents the multi-turn attack window, typically the conversation ID in production. It is required to detect escalation and crescendo-style jailbreaks that span multiple turns and bypass single-turn detection.


* **`name`**: Acts as a scoping dimension that identifies the specific feature or endpoint hit. It is used to determine event severity.


* **`model`**: Identifies routing anomalies, such as sensitive traffic unexpectedly served by a fallback model. It enables model-aware thresholds for tuning rules, as refusal phrasing and rates differ per model.


* **`tags`**: Operational tags (like environment or version) provide legitimate scoping context. Outcome labels (like injection or benign) provide ground truth for evaluation only and must never be used as detection inputs.


* **`latency`** & **`completion_tokens`**: Serve as weak per-event features. Short completions indicate refusals but also cause false positives on greetings or terse answers, requiring combination with other signals.


* **`input_content_user_role`**: Serves as the classifier's input and represents evidence of an attempt. Detections must key on derived features like structural anomalies, base64 blobs, or classifier scores, rather than raw text.


* **`output_content_assistant_role`**: Serves as evidence of effect to distinguish an attempt from a success. A canary in the output confirms exfiltration with near-zero false positives, while a refusal in the output confirms a blocked attempt.


### Failure Mode: Merged Traces (why `trace_id` and `session_id` are not interchangeable)

Observed in production data, not hypothetical: three semantically distinct
requests -- a benign question, a prompt injection, and a truncated
completion -- collapsed into a single Langfuse trace, accumulating for days
before it was noticed. The proximate cause: the client never set an
explicit `trace_id`, so LiteLLM's Langfuse callback derived one from
`session_id` instead. Since `session_id` is deliberately shared across a run
(and reused across reruns, by design), every request sharing that session
wrote into the same trace.

What broke, concretely:

* **`input`/`output` pairing became fabricated.** The stored `input` was
  the injection prompt; the stored `output` was the benign scenario's VPN
  answer. Any detection correlating prompt against completion was reading a
  pair that never actually happened together.
* **`tags` became the union of every outcome.** `benign`, `injection`, and
  `truncated` all landed on the same trace. Tag-based filtering selected
  everything, which is indistinguishable from selecting nothing.
* **`latency` stopped meaning request duration.** It measured the span
  between the first and last observation across days of runs (~49h in the
  observed case), not the time to serve one completion.
* **`observations` held entries from unrelated requests**, so anything
  iterating a trace's observations to reconstruct one interaction was
  actually reconstructing several, interleaved.

Why this matters more than it looks like it should: the merged trace is
still valid JSON, still has an `id`, a `sessionId`, `tags`, `input`, and
`output` -- every field a detection rule or a dashboard expects is present
and non-null. It is queryable. It looks like data. A rule built against it
runs, produces results, and is wrong in a way that isn't visible from the
output alone -- there is no error, no gap, no null field flagging the
problem. Missing data is at least legible as missing; this was worse,
because it required already knowing what a correct trace looks like to
notice anything was off. That is the general shape of the risk: telemetry
that is syntactically valid but semantically false is more dangerous than
telemetry that is absent, because absence gets noticed and silently-wrong
data does not.

The fix generalizes: **`trace_id` must be unique per request; `session_id`
must be shared across the requests that belong together.** They encode
different, non-substitutable groupings -- one request vs. one multi-turn
conversation -- and an ID scheme that lets one silently stand in for the
other will merge unrelated requests with no signal that it happened. Any
future field meant to identify "one distinct thing" should be checked for
this same failure mode: does something else in the pipeline quietly fall
back to a shared field when this one is left unset?

```mermaid
flowchart LR
    A["request A: benign question"] -->|"no trace_id set"| X["falls back to<br/>shared session_id"]
    B["request B: injection attempt"] -->|"no trace_id set"| X
    C["request C: truncated reply"] -->|"no trace_id set"| X
    X --> M["ONE merged trace:<br/>input from A, output from C,<br/>tags from A+B+C, latency spans days"]
```

### ECS mapping decisions: where the standard schema runs out

ECS (the Elastic Common Schema -- a shared vocabulary of field names, so
that different tools and different teams' data can be searched the same
way) has a `gen_ai.*` field group purpose-built for LLM telemetry:
`gen_ai.request.model`, `gen_ai.usage.input_tokens`, and so on. Every field
this project writes under `gen_ai.*` is checked, by hand, against Elastic's
own reference doc (`docs/reference/ecs-gen_ai.md`) before it's used --
see `internal/ecs/genai.go` for the field-by-field citations.

That reference doc has no field for the actual prompt or completion text.
This isn't an oversight -- OpenTelemetry (the standard ECS's Gen AI fields
are based on) deliberately keeps message content out of its span
attributes, because content is frequently sensitive and frequently large,
and a tracing standard meant for every possible LLM integration can't
assume it's always safe to store verbatim.

This project's own detections need that content -- the canary-token check
greps the response text; the prompt-injection check greps the request text.
So it lives under `llm.*` instead: a namespace this project invented,
clearly documented as *not* ECS everywhere it appears (see `internal/ecs`'s
package doc and `llm.go`), specifically so nobody mistakes it for a
standard field or assumes it means the same thing in a different system. If
ECS ever adds a real content field, `llm.*` is the thing to revisit.

The rule this project holds itself to: **a plausible-looking wrong field
name is worse than a missing one.** A field that doesn't exist fails loudly
-- the query returns nothing, and that's investigable. A field that exists
under the wrong name, or with the wrong type, *looks* like it's working and
silently answers a different question than the one being asked. Every
`gen_ai.*` field in this project was checked against the reference doc for
exactly this reason, not as a formality.

### Failure Mode: The Empty `gen_ai.*` Fields (a schema that validated, tested green, and emitted nothing)

Observed in this project's own history, not hypothetical: seven of the nine
`gen_ai.*` fields this project maps -- both token counts, the requested and
answering model names, the max-tokens setting, the response ID, and finish
reasons -- were permanently empty on every real document, from the first
commit that introduced `gen_ai.*` mapping up until this was diagnosed and
fixed. Not empty on some documents. Empty on all of them, silently, the
entire time.

The proximate cause: Langfuse's public API has two endpoints for reading a
trace back (see `arch.md`'s "Two Langfuse endpoints, one archive" section
for the full shape difference), and only one of them -- the list endpoint,
`GET /api/public/traces` -- was ever called by the fetch stage. The list
endpoint reduces each observation to a bare ID string. The detail endpoint,
`GET /api/public/traces/{id}`, returns the same observation as a full
object with `usage`, `model`, `metadata`, and `modelParameters` attached --
and every one of those seven fields reads from data that only exists on
that full object. A `GetTrace` function that called the detail endpoint
already existed in `internal/langfuse`, fully typed and unit-tested; it was
just never wired into the fetch stage that actually runs in production.
`internal/pipeline` only ever called `ListTraces`.

What makes this failure mode distinct from the merged-traces one above:
that one was silently *wrong* (a plausible-looking value that was actually
fabricated from unrelated data). This one was silently *absent* -- which
this project's own stated doctrine treats as the honest, lower-risk
outcome ("absence is at least legible as missing"). And in one sense that
doctrine held: nobody was misled by a fake token count, because there was
never a fake token count, only a missing one. But absence being *honest*
does not mean absence being *invisible* is acceptable, and here it was
invisible for a specific, structural reason:

* **The mapper was correct.** `internal/ecs/genai.go` read the right struct
  fields, under the right names, with the right types, cited against
  `docs/reference/ecs-gen_ai.md`. There was no bug to find by reading that
  file.
* **The tests were green.** `TestMap_NoGenAIFieldEmittedAsZeroSubstituteForMissing`
  specifically asserts that an absent field stays absent rather than being
  coerced to a zero value -- and it passed, correctly, on every run,
  because the fields genuinely were absent given the input the mapper was
  handed. The test was validating the right property; it just had no way
  to know the *input itself* was thinner than production data actually is.
* **The schema validated.** Every document indexed cleanly, matched its
  mapping, and was queryable. A dashboard built against `gen_ai.usage.*`
  would show real, legitimate-looking empty results -- not an error, not a
  missing index, just consistently nothing -- and "consistently nothing"
  is far more easily misread as "this traffic pattern has no token usage"
  than as "this pipeline never fetched the field."

The gap was never inside the boundary anyone was actually checking. It was
one layer upstream, in *what got fetched*, not in what got parsed or
mapped from what was fetched. This is why Task 1 of the fix that resolved
this was investigation-only, with an explicit instruction not to touch the
mapper to compensate: changing `internal/ecs/genai.go` to paper over a
fetch-layer gap would have made the mapper *wrong* to make the pipeline
*look* right, which is a strictly worse trade than the honest absence that
came before it.

```mermaid
flowchart LR
    A["fetch stage calls\nGET /api/public/traces (list)"] --> B["observations reduced to\nID strings only"]
    B --> C["parse: no usage/model data\nto read -- fields absent"]
    C --> D["mapper: correctly omits\nabsent fields (as designed)"]
    D --> E["ES: schema valid,\ndocument indexed, query clean"]
    E --> F["7 of 9 gen_ai.* fields\nempty on every document,\nno error anywhere"]
```

The fix generalizes past this one incident: **a green test suite proves the
code does what the test describes, not that the test describes what
production actually needs.** `TestMap_NoGenAIFieldEmittedAsZeroSubstituteForMissing`
was never wrong -- it just wasn't sufficient on its own, because nothing in
this project's test suite exercised the fetch stage against the *shape*
of data the detail endpoint actually returns until real captured fixtures
(`internal/langfuse/testdata/detail_truncated.json`,
`detail_benign.json`) were added specifically to close that gap. When a
field is unexpectedly, permanently absent across every record, the
question to ask before assuming "this data genuinely doesn't exist" is
"did every step between the source system and this field actually run,"
starting from the network call outward -- not just from the mapper
inward, which is the direction a bug usually gets looked for first.

### The canary-in-the-system-prompt trap (why detections must be scoped to output, not input)

Every scenario this project sends carries the same canary string
(`XK9-Canaries-77`) embedded in its *system prompt* -- the fixed
instructions the model is given before the user's message, invisible to
the user, present on literally every single request regardless of whether
that request is an attack. This is deliberate: the system prompt is where a
real deployment would put an actual secret it doesn't want leaked.

The trap: if a detection rule is scoped to check for the canary anywhere in
the *request* -- input, system prompt, the whole document -- it will match
every single trace this project ever produces, attack or not, because the
canary is *always* present on the input side. A detection that fires on
100% of traffic is not a detection; it's noise with extra steps, and it
will get disabled by whoever has to live with the alert volume.

The canary only means something when it shows up somewhere it shouldn't:
in the model's *output*. A model correctly following its instructions never
repeats the canary back; a model that's been successfully manipulated into
ignoring its system prompt might. That's why this project's canary
detection (see docs/DETECTIONS.md) is scoped to `llm.output` only, and why
`internal/ecs` has a test (`TestMap_CanaryOnlyInSystemPromptNeverInOutput`)
that fails loudly if the canary ever shows up in a mapped document's output
field across any of the three test scenarios -- a regression here would
mean either the detection query or the mapping itself is scoped wrong, and
either one silently turns a precise detection into permanent background
noise.

