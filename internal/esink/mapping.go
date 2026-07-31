package esink

// Field types, named once so a mapping reads as a schema rather than as a
// wall of map literals.
var (
	keyword       = map[string]any{"type": "keyword"}
	integer       = map[string]any{"type": "integer"}
	double        = map[string]any{"type": "double"}
	date          = map[string]any{"type": "date"}
	long          = map[string]any{"type": "long"}
	wildcard      = map[string]any{"type": "wildcard"}
	matchOnlyText = map[string]any{"type": "match_only_text"}
)

func props(p map[string]any) map[string]any { return map[string]any{"properties": p} }

// sharedProperties are the fields BOTH datasets emit, defined exactly
// once.
//
// This is the load-bearing part of the two-index design. Both indices sit
// behind one shared pattern (wiretap-llm-*) so a single Kibana data view
// and EQL sequence can span them -- and a field queried across that
// pattern must have the *same type* in both indices or the query fails or,
// worse, silently misbehaves. Elasticsearch does not warn about this; a
// cross-index query over a field mapped keyword in one place and text in
// another returns wrong results rather than an error.
//
// Defining them once here makes divergence structurally impossible rather
// than merely discouraged. TestSharedFieldsHaveIdenticalMappings still
// checks the *rendered* templates, because a future edit could override a
// shared field inside one dataset's own additions and this construction
// would not stop it.
//
// Every field below is emitted by internal/ecs's newDocument (the shared
// common-field builder), which is the code-side counterpart of this map:
// one place builds them, one place maps them.
func sharedProperties() map[string]any {
	return map[string]any{
		"@timestamp": date,
		"ecs":        props(map[string]any{"version": keyword}),
		"event": props(map[string]any{
			"kind":     keyword,
			"category": keyword,
			"type":     keyword,
			"action":   keyword,
			"dataset":  keyword,
			"module":   keyword,
			"outcome":  keyword,
			// event.start / event.end are what cross-plane correlation
			// compares -- @timestamp means a different instant per dataset
			// (see docs/CORRELATION.md §5), so these two being identically
			// mapped is what makes a sequence query across both indices
			// meaningful at all.
			"start":     date,
			"end":       date,
			"duration":  long,
			"ingested":  date,
			"reference": keyword,
		}),
		"trace":   props(map[string]any{"id": keyword}),
		"session": props(map[string]any{"id": keyword}),
		"user":    props(map[string]any{"id": keyword}),
		"gen_ai": props(map[string]any{
			"system":    keyword,
			"operation": props(map[string]any{"name": keyword}),
			"request": props(map[string]any{
				"model":      keyword,
				"max_tokens": integer,
			}),
			"response": props(map[string]any{
				"model": keyword,
				"id":    keyword,
				// No finish_reasons mapping: internal/ecs's genAIResponse
				// doesn't have that field. Confirmed genuinely unavailable
				// from this project's data -- mapping a field the document
				// never sends would be dead, misleading schema.
			}),
			"usage": props(map[string]any{
				"input_tokens":  integer,
				"output_tokens": integer,
			}),
		}),
		// error.* is emitted by both planes, though with different
		// completeness: the content plane has only message, the gateway
		// plane adds type and code. Mapping all three in both indices
		// keeps the shared pattern coherent -- a query for error.type
		// against the content index simply matches nothing, rather than
		// erroring on an unmapped field in a cross-index search.
		"error": props(map[string]any{
			// match_only_text is the type ECS itself declares: a
			// space-efficient variant of text for log-style messages that
			// are read and full-text searched but never scored or
			// phrase-position queried. Deliberately NOT wildcard: unlike
			// llm.output, no detection greps this for a mid-string exact
			// substring -- grouping happens on the structured error.type.
			"message": matchOnlyText,
			"type":    keyword,
			"code":    keyword,
		}),
		"related": props(map[string]any{"user": keyword}),
		"labels": props(map[string]any{
			"wiretap_outcome":  keyword,
			"wiretap_scenario": keyword,
		}),
		"tags": keyword,
	}
}

// contentIndexMapping is the explicit field mapping for the content plane
// (event.dataset "wiretap.langfuse"). No field is left to dynamic mapping.
//
// Two choices worth explaining inline rather than leaving implicit:
//
//   - llm.output and llm.user_prompt use Elasticsearch's "wildcard" type,
//     not "keyword" or "text". The canary-token detection this project
//     exists to demonstrate (see docs/DETECTIONS.md) is a leading-wildcard
//     query, llm.output: *XK9-Canaries-77*. Leading wildcards are slow (and
//     disabled by default) on "keyword", and "text"'s standard analyzer
//     tokenizes on non-alphanumeric characters, which would silently break
//     a substring match against a token containing punctuation or mixed
//     case. "wildcard" exists in Elasticsearch specifically for this
//     access pattern. Getting this one wrong doesn't break loudly -- the
//     query just quietly returns nothing.
//   - llm.messages is "text" with "index": false. It exists for an analyst
//     to read the full conversation when they click into a document, not
//     to be searched -- the fields that matter for detection are
//     llm.output and llm.user_prompt, already broken out separately.
//     Indexing the same content a second time would roughly double this
//     field's storage for a capability nothing in docs/DETECTIONS.md uses.
func contentIndexMapping() map[string]any {
	p := sharedProperties()
	p["llm"] = props(map[string]any{
		"system_prompt":  map[string]any{"type": "text"},
		"user_prompt":    wildcard,
		"output":         wildcard,
		"output_role":    keyword,
		"messages":       map[string]any{"type": "text", "index": false},
		"message_count":  integer,
		"output_length":  integer,
		"total_cost_usd": double,
		// generation_count: how many GENERATION observations contributed
		// to gen_ai.usage.* above. Small, bounded counter.
		"generation_count": integer,
		// errored_generation_count: how many of those the source reported
		// at ERROR level, i.e. how many times the proxy refused this
		// request.
		"errored_generation_count": integer,
	})
	return map[string]any{"properties": p}
}

// gatewayIndexMapping is the explicit field mapping for the gateway plane
// (event.dataset "wiretap.litellm").
//
// Note what is absent: every llm.* content field. The gateway never sees
// prompt or response text, and internal/ecs is tested to emit none of them
// (TestMapGateway_NoContentFieldsEverEmitted). Mapping them here anyway
// would be dead schema that invites someone to query llm.output across the
// shared pattern and quietly match gateway documents -- see notes.md's
// entry on the defect that lived between two correct decisions.
func gatewayIndexMapping() map[string]any {
	p := sharedProperties()
	p["llm"] = props(map[string]any{
		// Shared with the content plane -- both planes report cost, the
		// gateway is authoritative, and a disagreement between them is a
		// detection (docs/CORRELATION.md §4). Same type in both indices.
		"total_cost_usd": double,
		// The virtual key identity. keyword on both fields: these are
		// grouped and counted, never full-text searched. llm.key.hash in
		// particular is what auth-failure clustering aggregates on, and a
		// terms aggregation requires keyword.
		"key": props(map[string]any{
			"alias": keyword,
			"hash":  keyword,
		}),
	})
	// http.response.status_code is long, the type ECS declares for it.
	p["http"] = props(map[string]any{
		"response": props(map[string]any{"status_code": long}),
	})
	return map[string]any{"properties": p}
}
