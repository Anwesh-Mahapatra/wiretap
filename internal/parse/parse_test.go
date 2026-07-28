package parse

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wiretap/internal/model"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %q: %v", name, err)
	}
	return data
}

func TestParseLine_FullScenario(t *testing.T) {
	line := readFixture(t, "full_scenario.json")
	ev, err := ParseLine(line, 1)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}

	if ev.TraceID != "benign-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" {
		t.Errorf("TraceID = %q", ev.TraceID)
	}
	if ev.ProjectID != "cmrwcw1jr0006mg078bikhxe9" {
		t.Errorf("ProjectID = %q, want the direct projectId field", ev.ProjectID)
	}
	if ev.SessionID != "module4" || ev.UserID != "anwesh-lab" {
		t.Errorf("SessionID/UserID = %q/%q", ev.SessionID, ev.UserID)
	}
	if ev.TraceName != "wiretap-benign" || ev.Outcome != model.OutcomeBenign {
		t.Errorf("TraceName/Outcome = %q/%q", ev.TraceName, ev.Outcome)
	}
	if ev.Environment != "default" {
		t.Errorf("Environment = %q", ev.Environment)
	}
	if !ev.RequestTimestamp.Equal(time.Date(2026, 7, 28, 13, 53, 50, 100_000_000, time.UTC)) {
		t.Errorf("RequestTimestamp = %v", ev.RequestTimestamp)
	}
	if !ev.IngestTimestamp.Equal(time.Date(2026, 7, 28, 13, 53, 50, 623_000_000, time.UTC)) {
		t.Errorf("IngestTimestamp = %v", ev.IngestTimestamp)
	}
	if ev.Duration == nil || *ev.Duration != 842*time.Millisecond {
		t.Errorf("Duration = %v, want 842ms", ev.Duration)
	}
	if ev.TotalCost == nil || *ev.TotalCost != 0.000123 {
		t.Errorf("TotalCost = %v", ev.TotalCost)
	}
	if len(ev.Messages) != 2 || ev.Messages[0].Role != "system" || ev.Messages[1].Role != "user" {
		t.Fatalf("Messages = %+v", ev.Messages)
	}
	if ev.OutputContent == "" || ev.OutputRole != "assistant" {
		t.Errorf("OutputContent/OutputRole = %q/%q", ev.OutputContent, ev.OutputRole)
	}
	if ev.IsHealthCheck {
		t.Error("IsHealthCheck = true, want false")
	}
	// observations was full objects -> response model and token usage
	// should be populated.
	if ev.ResponseModel != "llama-3.3-70b-versatile" {
		t.Errorf("ResponseModel = %q", ev.ResponseModel)
	}
	if ev.InputTokens == nil || *ev.InputTokens != 45 {
		t.Errorf("InputTokens = %v", ev.InputTokens)
	}
	if ev.OutputTokens == nil || *ev.OutputTokens != 28 {
		t.Errorf("OutputTokens = %v", ev.OutputTokens)
	}
	if ev.Source != model.SourceLangfuse {
		t.Errorf("Source = %q", ev.Source)
	}
	if ev.SourceRef != "/project/clxyzproj123/traces/benign-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" {
		t.Errorf("SourceRef = %q", ev.SourceRef)
	}
	if string(ev.SourceRecord) != string(line) {
		t.Error("SourceRecord does not match original line byte-for-byte")
	}
	// Fields this source never populates (see package doc).
	if ev.RequestModel != "" || ev.MaxTokens != nil || ev.Temperature != nil ||
		ev.FinishReasons != nil || ev.ResponseID != "" {
		t.Errorf("expected RequestModel/MaxTokens/Temperature/FinishReasons/ResponseID unset, got %+v", ev)
	}
}

func TestParseLine_HealthCheck(t *testing.T) {
	ev, err := ParseLine(readFixture(t, "health_check.json"), 1)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if !ev.IsHealthCheck {
		t.Error("IsHealthCheck = false, want true")
	}
	if ev.TotalCost == nil || *ev.TotalCost != 0 {
		t.Errorf("TotalCost = %v, want a real, present 0 (not nil)", ev.TotalCost)
	}
	if len(ev.Messages) != 0 {
		t.Errorf("Messages = %+v, want empty", ev.Messages)
	}
}

func TestParseLine_NullUserAndSession(t *testing.T) {
	ev, err := ParseLine(readFixture(t, "null_user_session.json"), 1)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if ev.UserID != "" || ev.SessionID != "" {
		t.Errorf("UserID/SessionID = %q/%q, want empty for null input", ev.UserID, ev.SessionID)
	}
	if ev.TotalCost != nil {
		t.Errorf("TotalCost = %v, want nil for null totalCost", ev.TotalCost)
	}
	if ev.Outcome != "" {
		t.Errorf("Outcome = %q, want empty for a non-wiretap trace name", ev.Outcome)
	}
	if ev.ResponseModel != "" || ev.InputTokens != nil || ev.OutputTokens != nil {
		t.Errorf("expected no observation-detail fields for null observations, got %+v", ev)
	}
	// This fixture has no "projectId" key -- confirms the htmlPath
	// fallback still works when a real projectId field is ever absent.
	if ev.ProjectID != "clxyzproj123" {
		t.Errorf("ProjectID = %q, want the htmlPath-derived fallback value", ev.ProjectID)
	}
}

func TestParseLine_EmptyMessageArray(t *testing.T) {
	ev, err := ParseLine(readFixture(t, "empty_messages.json"), 1)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if len(ev.Messages) != 0 {
		t.Errorf("Messages = %+v, want empty", ev.Messages)
	}
	// observations was bare ID strings (list-endpoint shape) -> no detail.
	if ev.ResponseModel != "" || ev.InputTokens != nil {
		t.Errorf("expected no observation-detail fields for ID-string observations, got %+v", ev)
	}
}

func TestParseLine_MoreThanTwoMessagesPreservesOrder(t *testing.T) {
	ev, err := ParseLine(readFixture(t, "multi_turn.json"), 1)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	wantRoles := []string{"system", "user", "assistant", "user"}
	if len(ev.Messages) != len(wantRoles) {
		t.Fatalf("got %d messages, want %d: %+v", len(ev.Messages), len(wantRoles), ev.Messages)
	}
	for i, role := range wantRoles {
		if ev.Messages[i].Role != role {
			t.Errorf("Messages[%d].Role = %q, want %q", i, ev.Messages[i].Role, role)
		}
	}
	if ev.Messages[3].Content != "yes, still failing" {
		t.Errorf("Messages[3].Content = %q, want the last turn's content, not the first", ev.Messages[3].Content)
	}
}

func TestParseLine_MalformedLineReturnsLineError(t *testing.T) {
	line := readFixture(t, "malformed.json")
	_, err := ParseLine(line, 42)
	if err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
	var lerr *LineError
	if !errors.As(err, &lerr) {
		t.Fatalf("expected *LineError, got %T: %v", err, err)
	}
	if lerr.Line != 42 {
		t.Errorf("LineError.Line = %d, want 42", lerr.Line)
	}
	if lerr.Excerpt == "" {
		t.Error("LineError.Excerpt is empty")
	}
}

func TestParseLine_MissingIDReturnsLineError(t *testing.T) {
	_, err := ParseLine([]byte(`{"name":"wiretap-benign","timestamp":"2026-07-28T13:00:00Z"}`), 7)
	var lerr *LineError
	if !errors.As(err, &lerr) {
		t.Fatalf("expected *LineError for missing id, got %T: %v", err, err)
	}
	if lerr.Line != 7 {
		t.Errorf("LineError.Line = %d, want 7", lerr.Line)
	}
}

// TestLatencyConvertsToNanosecondDuration guards the exact conversion the
// ECS mapper depends on: Langfuse reports latency in fractional seconds,
// and it must become an integer-nanosecond time.Duration here, not stay a
// float or get rounded away.
func TestLatencyConvertsToNanosecondDuration(t *testing.T) {
	line := []byte(`{"id":"truncated-0810d587b1e97f3420d277f13c17c1c0","timestamp":"2026-07-28T13:53:53.370Z","name":"wiretap-truncated","latency":0.295,"tags":["wiretap","truncated"],"environment":"default","htmlPath":"/project/p/traces/t"}`)
	ev, err := ParseLine(line, 1)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if ev.Duration == nil {
		t.Fatal("Duration is nil")
	}
	if got, want := ev.Duration.Nanoseconds(), int64(295_000_000); got != want {
		t.Errorf("Duration.Nanoseconds() = %d, want %d", got, want)
	}
}

func TestParseLine_TagsPassThrough(t *testing.T) {
	ev, err := ParseLine(readFixture(t, "full_scenario.json"), 1)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	want := []string{"wiretap", "benign"}
	if len(ev.Tags) != len(want) {
		t.Fatalf("Tags = %v, want %v", ev.Tags, want)
	}
	for i := range want {
		if ev.Tags[i] != want[i] {
			t.Errorf("Tags[%d] = %q, want %q", i, ev.Tags[i], want[i])
		}
	}
}
