package model

import "testing"

// TestDocumentID_GatewayRetriesDoNotCollapse is the reason DocumentID
// exists rather than every caller writing ev.TraceID.
//
// Three retried attempts of one logical request share a trace ID and have
// distinct gateway request IDs. Keyed on trace ID, all three would land on
// the same _id and each would overwrite the last -- three enforcement
// events silently becoming one, and the retry-inflation evidence
// docs/DETECTIONS.md warns about erased at index time rather than merely
// miscounted at query time.
func TestDocumentID_GatewayRetriesDoNotCollapse(t *testing.T) {
	const sharedTrace = "injection-463ae362b9c6a92a5c26f986fd74406e"
	attempts := []*LLMEvent{
		{TraceID: sharedTrace, Source: SourceLiteLLM, Gateway: &GatewayDetail{RequestID: "04115689-19b6-4b86-912a-2fbc1b91e7ec"}},
		{TraceID: sharedTrace, Source: SourceLiteLLM, Gateway: &GatewayDetail{RequestID: "5ad9711a-d75c-43e4-8047-90ec9b9f6cbb"}},
		{TraceID: sharedTrace, Source: SourceLiteLLM, Gateway: &GatewayDetail{RequestID: "54a4582c-b0fe-4f5f-b86d-2cc9c49bef2b"}},
	}

	seen := map[string]bool{}
	for _, ev := range attempts {
		id := ev.DocumentID()
		if id == sharedTrace {
			t.Fatalf("gateway attempt keyed on the trace ID; all three retries would overwrite one document")
		}
		if seen[id] {
			t.Errorf("duplicate DocumentID %q across distinct attempts", id)
		}
		seen[id] = true
	}
	if len(seen) != 3 {
		t.Errorf("got %d distinct document IDs for 3 attempts, want 3", len(seen))
	}
}

func TestDocumentID(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   LLMEvent
		want string
	}{
		{
			name: "content event uses the trace ID",
			ev:   LLMEvent{TraceID: "t1", Source: SourceLangfuse},
			want: "t1",
		},
		{
			name: "gateway event uses the per-attempt request ID",
			ev:   LLMEvent{TraceID: "t1", Source: SourceLiteLLM, Gateway: &GatewayDetail{RequestID: "r1"}},
			want: "r1",
		},
		{
			// A gateway record that never carried the join key still has a
			// request ID, and is still indexable -- it simply cannot be
			// correlated. See join-baseline.json.
			name: "gateway event with no trace ID is still identifiable",
			ev:   LLMEvent{Source: SourceLiteLLM, Gateway: &GatewayDetail{RequestID: "r1"}},
			want: "r1",
		},
		{
			// "" means do not index. Letting Elasticsearch auto-generate
			// an ID here would create a fresh document on every replay,
			// which is the duplicate-on-backfill failure this guards.
			name: "no identifier at all is empty, not substituted",
			ev:   LLMEvent{Source: SourceLangfuse},
			want: "",
		},
		{
			name: "gateway event with an empty request ID does not fall back to the trace ID",
			ev:   LLMEvent{TraceID: "t1", Source: SourceLiteLLM, Gateway: &GatewayDetail{}},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ev.DocumentID(); got != tc.want {
				t.Errorf("DocumentID() = %q, want %q", got, tc.want)
			}
		})
	}
}
