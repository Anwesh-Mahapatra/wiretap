//go:build ignore

// tracescope fetches a single Langfuse trace via the public API and prints a
// flattened, human-readable view of it.
//
// Usage: go run tracescope.go <traceId>
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultEnvFile     = ".env"
	defaultLangfuseURL = "http://localhost:3000"
)

type apiUsage struct {
	Input  int    `json:"input"`
	Output int    `json:"output"`
	Total  int    `json:"total"`
	Unit   string `json:"unit"`
}

type apiObservation struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	Model     string    `json:"model"`
	Input     any       `json:"input"`
	Output    any       `json:"output"`
	Usage     *apiUsage `json:"usage"`
	Latency   float64   `json:"latency"`
	StartTime string    `json:"startTime"`
	EndTime   string    `json:"endTime"`
}

type apiTrace struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	UserID       string           `json:"userId"`
	SessionID    string           `json:"sessionId"`
	Tags         []string         `json:"tags"`
	Input        any              `json:"input"`
	Output       any              `json:"output"`
	Latency      float64          `json:"latency"`
	Observations []apiObservation `json:"observations"`
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// loadDotEnv populates the environment from a simple KEY="value" file, one
// assignment per line. Existing environment variables always take
// precedence. Missing file is not an error since .env is optional.
func loadDotEnv(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading %q: %w", path, err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)

		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
		}
	}
	return nil
}

func fetchTrace(baseURL, publicKey, secretKey, traceID string) (*apiTrace, error) {
	url := fmt.Sprintf("%s/api/public/traces/%s", strings.TrimRight(baseURL, "/"), traceID)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.SetBasicAuth(publicKey, secretKey)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("langfuse API returned status %s: %s", resp.Status, body)
	}

	var trace apiTrace
	if err := json.Unmarshal(body, &trace); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return &trace, nil
}

func printJSONField(label string, v any) {
	if v == nil {
		fmt.Printf("%s: (none)\n", label)
		return
	}
	b, err := json.MarshalIndent(v, "    ", "  ")
	if err != nil {
		fmt.Printf("%s: %v\n", label, v)
		return
	}
	fmt.Printf("%s:\n    %s\n", label, b)
}

func printTrace(t *apiTrace) {
	fmt.Printf("trace id:   %s\n", t.ID)
	fmt.Printf("name:       %s\n", t.Name)
	fmt.Printf("userId:     %s\n", t.UserID)
	fmt.Printf("sessionId:  %s\n", t.SessionID)
	fmt.Printf("tags:       %s\n", strings.Join(t.Tags, ", "))
	fmt.Println()

	generations := 0
	for _, obs := range t.Observations {
		if obs.Type != "GENERATION" {
			continue
		}
		generations++

		fmt.Printf("--- generation: %s ---\n", obs.Name)
		fmt.Printf("model:              %s\n", obs.Model)
		fmt.Printf("latency (s):        %.3f\n", obs.Latency)
		if obs.Usage != nil {
			fmt.Printf("prompt tokens:      %d\n", obs.Usage.Input)
			fmt.Printf("completion tokens:  %d\n", obs.Usage.Output)
		} else {
			fmt.Printf("prompt tokens:      (none)\n")
			fmt.Printf("completion tokens:  (none)\n")
		}
		printJSONField("input", obs.Input)
		printJSONField("output", obs.Output)
		fmt.Println()
	}

	if generations == 0 {
		fmt.Println("(no generations found on this trace)")
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run tracescope.go <traceId>")
		os.Exit(1)
	}
	traceID := os.Args[1]

	if err := run(traceID); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(traceID string) error {
	if err := loadDotEnv(defaultEnvFile); err != nil {
		return err
	}

	publicKey := os.Getenv("LANGFUSE_PUBLIC_KEY")
	secretKey := os.Getenv("LANGFUSE_SECRET_KEY")
	if publicKey == "" || secretKey == "" {
		return fmt.Errorf("LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY must be set (in the environment or .env)")
	}
	baseURL := envOrDefault("LANGFUSE_BASE_URL", defaultLangfuseURL)

	trace, err := fetchTrace(baseURL, publicKey, secretKey, traceID)
	if err != nil {
		return err
	}

	printTrace(trace)
	return nil
}
