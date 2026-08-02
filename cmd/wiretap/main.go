package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"

	"wiretap/internal/env"
)

const (
	defaultLiteLLMURL = "http://localhost:4000"
	defaultEnvFile    = ".env"
	requestTimeout    = 120 * time.Second
)

type scenarioMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type scenario struct {
	Name      string            `json:"name"`
	Tags      []string          `json:"tags"`
	MaxTokens *int64            `json:"maxTokens"`
	Messages  []scenarioMessage `json:"messages"`
}

type scenarioDefaults struct {
	Model     string `json:"model"`
	UserID    string `json:"userId"`
	SessionID string `json:"sessionId"`
}

type scenarioFile struct {
	Defaults  scenarioDefaults `json:"defaults"`
	Scenarios []scenario       `json:"scenarios"`
}

func loadScenarios(path string) (*scenarioFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}

	var sf scenarioFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("parsing %q: %w", path, err)
	}
	return &sf, nil
}

func toChatMessage(m scenarioMessage) openai.ChatCompletionMessageParamUnion {
	switch m.Role {
	case "system":
		return openai.SystemMessage(m.Content)
	case "assistant":
		return openai.AssistantMessage(m.Content)
	default:
		return openai.UserMessage(m.Content)
	}
}

// newTraceID returns a fresh, scenario-prefixed identifier for use as
// metadata.trace_id, e.g. "injection-3f9a2c8b1d4e5f60...". The scenario name
// prefix lets an analyst read the scenario straight off a trace ID when
// pivoting from a Kibana alert into the Langfuse UI, without an extra
// lookup. 16 random bytes (128 bits) from crypto/rand is more than enough
// entropy to guarantee a fresh ID on every call, including reruns of the
// same scenario.
func newTraceID(scenarioName string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating trace id: %w", err)
	}
	return fmt.Sprintf("%s-%x", scenarioName, b), nil
}

var authHeaderRe = regexp.MustCompile(`(?i)^(Authorization:\s*Bearer\s+).+$`)

// redactDump masks the bearer token in a dumped HTTP request/response so the
// API key never ends up in stdout, logs, or terminal scrollback.
func redactDump(dump []byte) []byte {
	lines := strings.Split(string(dump), "\r\n")
	for i, line := range lines {
		lines[i] = authHeaderRe.ReplaceAllString(line, "${1}[REDACTED]")
	}
	return []byte(strings.Join(lines, "\r\n"))
}

// dumpRequestMiddleware prints the raw outgoing HTTP request alongside the
// response, matching the io.Writer view of what actually goes over the wire.
func dumpRequestMiddleware(req *http.Request, next option.MiddlewareNext) (*http.Response, error) {
	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return nil, fmt.Errorf("dumping request: %w", err)
	}
	fmt.Printf("--- request ---\n%s\n", redactDump(dump))

	res, err := next(req)
	if err != nil {
		return res, err
	}

	respDump, err := httputil.DumpResponse(res, true)
	if err != nil {
		return nil, fmt.Errorf("dumping response: %w", err)
	}
	fmt.Printf("--- response ---\n%s\n", respDump)

	return res, err
}

func loadWiretapKey() (string, error) {
	key := os.Getenv("WIRETAP_KEY")
	if key == "" {
		return "", fmt.Errorf("WIRETAP_KEY must be set (in the environment or .env)")
	}
	return key, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	// The target model is a runtime choice, not an edit: scenarios.json's
	// defaults.model is the default, -model switches backend for one run
	// (e.g. `-model local-llama` for volume against Ollama, `-model
	// llama-3.3-70b-versatile` for a Groq spot-check). Editing the
	// scenario file to switch backends was the working-tree hack this
	// flag replaces.
	modelFlag := flag.String("model", "", "LiteLLM model alias to send scenarios to; overrides scenarios.json's defaults.model")
	flag.Parse()

	if err := env.LoadDotEnv(defaultEnvFile); err != nil {
		return err
	}

	apiKey, err := loadWiretapKey()
	if err != nil {
		return err
	}

	sf, err := loadScenarios("scenarios.json")
	if err != nil {
		return err
	}

	model := *modelFlag
	if model == "" {
		model = sf.Defaults.Model
	}
	if model == "" {
		return fmt.Errorf("no target model: pass -model or set defaults.model in scenarios.json")
	}
	fmt.Printf("target model: %s (%d scenarios)\n", model, len(sf.Scenarios))

	// LiteLLM proxies to the configured backends (see model_list in
	// config.yaml) and reports telemetry to Langfuse itself (see
	// litellm_settings.success_callback), so no Go-side tracing
	// middleware is needed here anymore.
	client := openai.NewClient(
		option.WithBaseURL(env.OrDefault("LITELLM_BASE_URL", defaultLiteLLMURL)),
		option.WithAPIKey(apiKey),
		option.WithMiddleware(dumpRequestMiddleware),
	)

	type result struct {
		name       string
		ok         bool
		httpStatus int
		traceID    string
		err        error
	}
	results := make([]result, 0, len(sf.Scenarios))

	for _, sc := range sf.Scenarios {
		traceID, err := newTraceID(sc.Name)
		if err != nil {
			return fmt.Errorf("scenario %q: %w", sc.Name, err)
		}
		// Fail loudly rather than silently repeating the merged-trace bug:
		// if this ever matches the shared session ID, LiteLLM's Langfuse
		// callback would collapse every scenario back into one trace.
		if traceID == sf.Defaults.SessionID {
			return fmt.Errorf("scenario %q: generated trace id %q equals session id %q -- refusing to send, this would merge traces again", sc.Name, traceID, sf.Defaults.SessionID)
		}

		messages := make([]openai.ChatCompletionMessageParamUnion, len(sc.Messages))
		for i, m := range sc.Messages {
			messages[i] = toChatMessage(m)
		}

		params := openai.ChatCompletionNewParams{
			Model:    model,
			Messages: messages,
		}
		if sc.MaxTokens != nil {
			params.MaxTokens = openai.Int(*sc.MaxTokens)
		}

		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		resp, err := client.Chat.Completions.New(ctx, params,
			option.WithJSONSet("metadata.trace_user_id", sf.Defaults.UserID),
			option.WithJSONSet("metadata.session_id", sf.Defaults.SessionID),
			option.WithJSONSet("metadata.tags", sc.Tags),
			option.WithJSONSet("metadata.trace_name", "wiretap-"+sc.Name),
			// Without this, LiteLLM's Langfuse callback derives the trace ID
			// from session_id instead. Since session_id is intentionally
			// shared across a whole run (and across reruns, per
			// scenarios.json), every scenario -- and every prior run using
			// the same session ID -- would collapse into a single Langfuse
			// trace: input/output pairs from different requests get
			// shuffled together, tags become the union of every outcome,
			// and latency spans days instead of one request. This is not
			// hypothetical; it already happened once. See notes.md.
			option.WithJSONSet("metadata.trace_id", traceID),
			// The same ID again, under the one key LiteLLM preserves into
			// its own spend records. metadata.trace_id above reaches
			// Langfuse (the content plane) and nothing else; LiteLLM does
			// not forward arbitrary caller metadata into LiteLLM_SpendLogs,
			// so without this line the gateway plane has no idea which
			// request it is looking at and no cross-plane join is possible.
			//
			// Sending the same value twice under two keys is redundant and
			// is the price of an exact join that also covers *refused*
			// requests. The alternative join key -- the completion ID,
			// which LiteLLM uses as the spend record's request_id -- only
			// exists when a completion happened, so it covers precisely the
			// requests the gateway plane is least needed for. A budget
			// block or an auth failure has no completion ID, and
			// session_id is no help either: LiteLLM discards the caller's
			// session_id on a refusal and substitutes a random UUID.
			// See docs/CORRELATION.md §2.
			option.WithJSONSet("metadata.spend_logs_metadata.trace_id", traceID),
		)
		cancel()
		if err != nil {
			res := result{name: sc.Name, traceID: traceID, err: fmt.Errorf("sending request: %w", err)}
			if apiErr, ok := errors.AsType[*openai.Error](err); ok {
				res.httpStatus = apiErr.StatusCode
			}
			results = append(results, res)
			fmt.Fprintf(os.Stderr, "scenario %q: trace=%s: %v\n", sc.Name, traceID, res.err)
			continue
		}

		fmt.Printf("=== %s (trace=%s) ===\n%s\n", sc.Name, traceID, resp.Choices[0].Message.Content)
		results = append(results, result{name: sc.Name, ok: true, httpStatus: http.StatusOK, traceID: traceID})
	}

	fmt.Println("\n=== summary ===")
	failed := false
	for _, r := range results {
		status := "ok"
		if !r.ok {
			status = "failed"
			failed = true
		}
		if r.httpStatus != 0 {
			fmt.Printf("%-12s %-7s http=%-6d trace=%s\n", r.name, status, r.httpStatus, r.traceID)
		} else {
			fmt.Printf("%-12s %-7s http=(none) trace=%s\n", r.name, status, r.traceID)
		}
	}

	if failed {
		return fmt.Errorf("one or more scenarios failed")
	}
	return nil
}
