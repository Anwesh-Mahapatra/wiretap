// Package env provides small configuration-loading helpers shared by
// wiretap's command-line tools (the root wiretap binary, tracescope, and
// tracepump).
package env

import (
	"fmt"
	"os"
	"strings"
)

// OrDefault returns the environment variable named key, or def if it is
// unset or empty.
func OrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// LoadDotEnv populates the environment from a simple KEY="value" file, one
// assignment per line. Existing environment variables always take
// precedence. Missing file is not an error since .env is optional.
func LoadDotEnv(path string) error {
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
