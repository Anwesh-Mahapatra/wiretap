# Architecture

This explains how wiretap's pieces fit together, and *why* — not just what
each one does. Terms are explained the first time they show up, on the
assumption you might not have worked with proxies, message queues, or
search-engine schemas before.

## The two log sources: gateway vs. content

Two different systems each see half of every request, and neither half
tells the whole story alone.

- **The gateway log**, written by LiteLLM (the "proxy" every chat request
  passes through — "proxy" just means a server that sits in the middle and
  forwards requests on your behalf, the way a mail-forwarding service
  redirects letters to your new address). The gateway knows *who* called,
  *which model* they asked for, *when*, whether it *succeeded*, how many
  *tokens* it used (a token is roughly one word or word-fragment — it's how
  LLM providers measure and bill usage), and what it *cost*. It does not
  reliably know *what was actually said*: routing and accounting are its
  job, not transcription.
- **The content log**, written by Langfuse (a "tracing" tool wired into the
  same request path — tracing means recording a detailed timeline of one
  request: what went in, what came out, how long each step took). Langfuse
  knows the *actual prompt and response text*, but has a much thinner
  picture of authentication, quota enforcement, or billing.

A detection like "flag any request where the model actually leaked our
canary secret" only needs the content log. A detection like "this user is
suddenly making 50x their normal request volume" only needs the gateway
log. A detection like "this user's *requests are failing enforcement* at an
unusual rate" needs both, joined by a shared ID.

wiretap currently only builds the content-log half of this (Langfuse →
Elasticsearch). The gateway-log half is a real, tracked gap — see
[docs/DETECTIONS.md](docs/DETECTIONS.md) for exactly which detections are
blocked on it.

```mermaid
flowchart TB
    subgraph gateway["Gateway log (LiteLLM) — built in Module 5+, not yet"]
        G1["who called"]
        G2["which model"]
        G3["tokens & cost"]
        G4["blocked / allowed"]
    end
    subgraph content["Content log (Langfuse) — what wiretap builds today"]
        C1["the actual prompt"]
        C2["the actual response"]
    end
    gateway -->|joined by a shared trace ID| both["Full picture:<br/>who said what, and what happened to it"]
    content -->|joined by a shared trace ID| both
```

## Why a plain file sits in the middle of the pipeline

```mermaid
flowchart LR
    A[("Langfuse")] -->|"fetch"| B[("NDJSON archive<br/>— a plain file, one<br/>JSON record per line")]
    B -->|"parse, map, ship"| C[("Elasticsearch")]
```

It would be simpler to fetch a record from Langfuse and immediately push it
into Elasticsearch, with nothing in between. wiretap deliberately doesn't do
that, for one reason: **the archive is a durable buffer, and the two halves
of the pipeline fail independently.**

If Elasticsearch is down, or a mapping bug ships and needs fixing, the
archive means you never have to go back and re-ask Langfuse for the same
data — you already have it on disk, and you replay it (`wiretapd backfill`)
straight through the fixed code. Without the archive, a mapping bug found a
week later would mean either accepting the bad data forever or replaying
history from Langfuse's own retention window, if it even still has it.
Fetching from Langfuse and shipping to Elasticsearch becoming two separate,
independently-retriable steps — rather than one step that has to succeed
atomically — is the entire reason this project has a `Fetcher` and an
`Indexer` (see `internal/pipeline`) instead of one combined stage, and the
entire reason they keep *two separate checkpoints* instead of one: an
Elasticsearch outage stalls the indexer's checkpoint, but the fetcher keeps
right on pulling from Langfuse regardless, because nothing ties them
together except the file.

## Two Langfuse endpoints, one archive: the enrichment tradeoff

Langfuse's public API has two different ways to ask about a trace, and
they return meaningfully different amounts of detail:

| Endpoint | What it returns |
|---|---|
| `GET /api/public/traces` (list, paginated) | Every trace on the page, but each one's `observations` field is just an array of ID strings — a pointer, not the data. |
| `GET /api/public/traces/{id}` (detail, one trace) | The same trace, but `observations` is now an array of full objects — and only those full objects carry token counts, the model that actually answered, and a few other fields this project needs. |

For a while, this project's fetch stage only ever called the list
endpoint. Every trace still got archived and indexed — but with
`observations` reduced to bare ID strings, none of the token-count or
model-name fields in `gen_ai.*` had anything to read, so they were always
absent. Every test still passed (correctly: absent is the honest
representation of "we never fetched that data," not a bug), and the
mapper's own code was never at fault — the gap was entirely in what got
fetched. See `notes.md` for this as a worked example.

The fix, called **enrichment** in this codebase, is straightforward in
concept and has one real cost: for every new trace the list endpoint
reports, the fetch stage now makes a *second* API call to the detail
endpoint to get the full observation objects, then archives that richer
response instead of the list-shaped one. That's **N+1 requests** for a
page of N new traces — a real, ongoing cost in API calls against Langfuse,
traded for fields that would otherwise always be empty. `internal/pipeline`
bounds this with a small worker pool (4 concurrent requests by default,
configurable) rather than firing all N at once, and treats a single
trace's enrichment failure as *that trace's* problem — skipped and
retried on the next poll — rather than letting one flaky request block
every other trace on the page. See `internal/pipeline/enrich.go`'s own
doc comments for the retry/backoff coordination details.

```mermaid
sequenceDiagram
    participant WD as wiretapd (fetch stage)
    participant LF as Langfuse

    WD->>LF: GET /api/public/traces (list, page N)
    LF-->>WD: traces, each with observations: ["id1", "id2", ...]

    loop for each new trace, bounded concurrency
        WD->>LF: GET /api/public/traces/{id} (detail)
        LF-->>WD: same trace, observations: [{full object}, ...]
        WD->>WD: archive the DETAIL response<br/>(not the list one)
    end
```

The archive still holds exactly one real API response per line, byte-for-
byte, faithful to what Langfuse actually sent — enrichment changes *which*
response gets archived (detail instead of list), never rewrites one after
the fact. That property is what makes `wiretapd backfill` safe here too:
replaying the archive re-parses real, complete API responses, not a
patched-up approximation of one.

## Why parsing and mapping are two separate steps (`internal/model`)

Langfuse's JSON shape is an *input* detail. ECS's field names are an
*output* detail. What actually matters — one LLM request, its prompt, its
response, its cost — is neither of those; it's the thing both of them are
trying to describe. `internal/model.LLMEvent` is that thing, written down
as a Go struct that doesn't know Langfuse's field names and doesn't know
ECS's field names either.

```mermaid
flowchart LR
    A["Langfuse JSON<br/>(input format)"] -->|"internal/parse"| B["model.LLMEvent<br/>(what it actually means)"]
    B -->|"internal/ecs"| C["ECS document<br/>(output format)"]
```

The payoff isn't abstract. This project's own `notes.md` documents a real
incident where trace data got silently corrupted (the "merged traces"
failure mode) — and the fix was possible to reason about clearly *because*
the parsing step and the meaning of the data were separated from how it
eventually gets displayed. More concretely: when this project eventually
adds a second data source (LiteLLM's own gateway logs, closing the gap
described above), that becomes a second file in `internal/parse` that
produces the same `LLMEvent` shape — `internal/ecs` doesn't change at all,
because it never knew Langfuse existed in the first place.

## Regular index + alias, not a data stream — and the ID tradeoff that drove it

Elasticsearch (the search engine everything ends up in) offers a purpose-
built structure for exactly this kind of data — a continuous stream of
timestamped events — called a **data stream**. It handles a lot of
bookkeeping automatically (rolling over to a new backing index as data
grows, applying retention policies). wiretap doesn't use one.

The reason is one specific feature data streams give up: control over a
document's own ID. Elasticsearch calls the unique identifier for one record
its `_id`. wiretap sets `_id` to the trace ID — the same ID Langfuse itself
assigned — for every document it indexes. That one choice is what makes
`wiretapd backfill` (re-read the whole archive and re-index everything,
after fixing a mapping bug) *safe to run as many times as you want*:
indexing the same trace ID twice doesn't create a duplicate, it just
overwrites the same document with the same (or corrected) content. Data
streams either forbid setting your own `_id` or make it awkward, because
they're optimized for the assumption that every write is a new, distinct
event. wiretap's writes are frequently the *same* event, re-sent on
purpose, and that idempotency (a fancy word for "doing it twice has the
same effect as doing it once") was worth more here than the rollover
convenience a data stream would have given for free. That tradeoff is
recorded directly in `internal/esink`'s own code comments, next to the
decision it explains.

## Why `llm.output` and `llm.user_prompt` use the "wildcard" field type

Elasticsearch needs to know, in advance, how to store and search each field
— this is called a field's **mapping**, and getting it wrong for a field
doesn't usually error, it just makes searches against it quietly return
nothing. Three relevant mapping types:

- **`keyword`** — stored and matched as one exact, whole value. Fast, but
  can't efficiently search for a hidden substring in the middle of a long
  value.
- **`text`** — broken up into individual words (this is called
  *analysis*), so you can search "did this contain the word X anywhere,"
  but punctuation-adjacent substrings and exact phrasing get lost in the
  process. A hyphenated token like `XK9-Canaries-77` gets split into
  pieces, so a search for the *exact* string would silently fail.
- **`wildcard`** — built specifically for "does this contain this exact
  substring, anywhere," including a leading wildcard (`*something*`),
  without either of the above two problems.

This project's flagship detection — did the model leak a secret canary
token embedded in its own instructions? — is exactly that access pattern: a
short, exact substring that could appear anywhere inside a long response.
`llm.output` and `llm.user_prompt` are mapped `wildcard` for this reason and
this reason alone; every other text-shaped field in this schema uses
`keyword` or plain `text` because nothing else needs a mid-string,
leading-wildcard search. Get this mapping wrong and the detection doesn't
crash — it just silently never fires. See `internal/esink`'s mapping code
for the field-by-field reasoning, and
[docs/DETECTIONS.md](docs/DETECTIONS.md) for the actual query this mapping
exists to support.

## End-to-end sequence

`wiretapd` is the only ingestion service in the default deployment: it
fetches from Langfuse (enriching each new trace as it goes, see above),
archives, maps, and indexes, all in one process with two independently-
paced loops sharing nothing but the archive file (see "why a plain file
sits in the middle," above, for why that's deliberate). An earlier
revision of this stack split fetching into a second, separate service
(`tracepump`) — removed once it became clear that combination could leave
enrichment silently never running at all (see `notes.md`'s worked
example) and risked a real timing race between two independent fetchers
writing the same archive. `cmd/tracepump` still exists as a standalone
tool for anyone who specifically wants a plain, unenriched, faithful pipe
with nothing else attached; it's just not part of the default compose
services anymore.

```mermaid
sequenceDiagram
    participant You as You
    participant WT as wiretap (cmd/wiretap)
    participant LL as LiteLLM
    participant Groq as Groq
    participant LF as Langfuse
    participant WD as wiretapd
    participant Archive as NDJSON archive
    participant ES as Elasticsearch
    participant KB as Kibana

    You->>WT: go run ./cmd/wiretap
    WT->>LL: chat request (tagged benign/injection/truncated)
    LL->>Groq: forwarded request
    Groq-->>LL: response
    LL-->>WT: response
    LL--)LF: log prompt + response (async)

    loop every 30s: fetch
        WD->>LF: poll for new traces (list)
        LF-->>WD: new trace IDs
        WD->>LF: fetch full detail per new trace (enrichment)
        LF-->>WD: enriched trace JSON
        WD->>Archive: append line (unmodified, once fetched)
    end

    loop every 10s: index
        WD->>Archive: read new lines
        WD->>WD: parse -> LLMEvent -> ECS document
        WD->>ES: bulk index (_id = trace ID)
    end

    You->>KB: search / build detection
    KB->>ES: query
    ES-->>KB: results
```
