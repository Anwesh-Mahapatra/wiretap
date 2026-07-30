package langfuse

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// loadFixture reads a captured real GET /api/public/traces/{id} response
// from testdata/. These are genuine responses from this project's own lab
// Langfuse instance -- see internal/langfuse/testdata's fixtures for the
// full raw shape. Nothing in them is redacted except the general absence
// of any real credential in the first place (verified when they were
// captured): the LiteLLM master key never appears in Langfuse's own
// telemetry, which reports "litellm_proxy_master_key" as a symbolic
// caller label, not the key value.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %q: %v", name, err)
	}
	return data
}

// TestTrace_DecodesRealDetailResponse_Truncated locks in every field this
// project relies on against a real, captured GetTrace response for a trace
// whose scenario set maxTokens: 5 -- the fixture that proves
// ModelParameters.MaxTokens is actually populated when the caller set it.
func TestTrace_DecodesRealDetailResponse_Truncated(t *testing.T) {
	var tr Trace
	if err := json.Unmarshal(loadFixture(t, "detail_truncated.json"), &tr); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}

	if tr.ID != "truncated-d1b6a7ef2d5936e1dc66cec92fa7c75e" {
		t.Errorf("Trace.ID = %q", tr.ID)
	}
	if len(tr.Observations) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(tr.Observations))
	}
	obs := tr.Observations[0]

	if obs.Type != "GENERATION" {
		t.Errorf("Observation.Type = %q, want GENERATION", obs.Type)
	}
	if obs.Model != "groq/llama-3.3-70b-versatile" {
		t.Errorf("Observation.Model (the answering model) = %q", obs.Model)
	}
	if obs.Metadata.ModelGroup != "llama-3.3-70b-versatile" {
		t.Errorf("Observation.Metadata.ModelGroup (the requested model) = %q", obs.Metadata.ModelGroup)
	}
	if obs.Model == obs.Metadata.ModelGroup {
		t.Error("Observation.Model and Metadata.ModelGroup are equal -- the whole point of this fixture is that they differ")
	}

	if obs.ModelParameters.MaxTokens == nil {
		t.Fatal("ModelParameters.MaxTokens is nil, want a real, present 5")
	}
	if *obs.ModelParameters.MaxTokens != 5 {
		t.Errorf("ModelParameters.MaxTokens = %d, want 5 (matches scenarios.json's maxTokens for this scenario)", *obs.ModelParameters.MaxTokens)
	}

	if obs.Usage == nil {
		t.Fatal("Usage is nil")
	}
	if obs.Usage.Input != 70 || obs.Usage.Output != 5 {
		t.Errorf("Usage = %+v, want Input=70 Output=5", obs.Usage)
	}

	id, ok := obs.CompletionID()
	if !ok {
		t.Fatal("CompletionID() ok = false, want true")
	}
	if id != "chatcmpl-da63253c-b51b-4557-9cc4-c3ed0aa1b9dd" {
		t.Errorf("CompletionID() = %q", id)
	}
}

// TestTrace_DecodesRealDetailResponse_Benign is the contrast fixture: a
// scenario that set no maxTokens at all, proving ModelParameters.MaxTokens
// comes back nil -- genuinely absent, not present-and-zero -- rather than
// picking up some default.
func TestTrace_DecodesRealDetailResponse_Benign(t *testing.T) {
	var tr Trace
	if err := json.Unmarshal(loadFixture(t, "detail_benign.json"), &tr); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}

	if len(tr.Observations) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(tr.Observations))
	}
	obs := tr.Observations[0]

	if obs.ModelParameters.MaxTokens != nil {
		t.Errorf("ModelParameters.MaxTokens = %v, want nil (this scenario set no maxTokens)", *obs.ModelParameters.MaxTokens)
	}
	if obs.Metadata.ModelGroup != "llama-3.3-70b-versatile" {
		t.Errorf("Observation.Metadata.ModelGroup = %q", obs.Metadata.ModelGroup)
	}

	id, ok := obs.CompletionID()
	if !ok || id == "" {
		t.Fatalf("CompletionID() = %q, %v, want a real non-empty ID", id, ok)
	}
}

func TestObservation_CompletionID_NoUnderscore(t *testing.T) {
	obs := Observation{ID: "no-underscore-here"}
	if _, ok := obs.CompletionID(); ok {
		t.Error("CompletionID() ok = true for an ID with no underscore, want false")
	}
}
