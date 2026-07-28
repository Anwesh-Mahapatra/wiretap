package main

import (
	"context"
	"encoding/json"
	"errors"
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
	requestTimeout    = 30 * time.Second
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

	// LiteLLM proxies to Groq and reports telemetry to Langfuse itself
	// (see litellm_settings.success_callback in config.yaml), so no Go-side
	// tracing middleware is needed here anymore.
	client := openai.NewClient(
		option.WithBaseURL(env.OrDefault("LITELLM_BASE_URL", defaultLiteLLMURL)),
		option.WithAPIKey(apiKey),
		option.WithMiddleware(dumpRequestMiddleware),
	)

	type result struct {
		name       string
		ok         bool
		httpStatus int
		err        error
	}
	results := make([]result, 0, len(sf.Scenarios))

	for _, sc := range sf.Scenarios {
		messages := make([]openai.ChatCompletionMessageParamUnion, len(sc.Messages))
		for i, m := range sc.Messages {
			messages[i] = toChatMessage(m)
		}

		params := openai.ChatCompletionNewParams{
			Model:    sf.Defaults.Model,
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
		)
		cancel()
		if err != nil {
			res := result{name: sc.Name, err: fmt.Errorf("sending request: %w", err)}
			if apiErr, ok := errors.AsType[*openai.Error](err); ok {
				res.httpStatus = apiErr.StatusCode
			}
			results = append(results, res)
			fmt.Fprintf(os.Stderr, "scenario %q: %v\n", sc.Name, res.err)
			continue
		}

		fmt.Printf("=== %s ===\n%s\n", sc.Name, resp.Choices[0].Message.Content)
		results = append(results, result{name: sc.Name, ok: true, httpStatus: http.StatusOK})
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
			fmt.Printf("%-12s %-7s http=%d\n", r.name, status, r.httpStatus)
		} else {
			fmt.Printf("%-12s %-7s http=(none)\n", r.name, status)
		}
	}

	if failed {
		return fmt.Errorf("one or more scenarios failed")
	}
	return nil
}
