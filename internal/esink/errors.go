package esink

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// ErrorKind classifies why a Client call failed.
type ErrorKind int

const (
	ErrUnknown ErrorKind = iota
	ErrAuth
	ErrRetryable // 429, 503, or a transport-level failure -- worth retrying
	ErrPermanent // 400, 404, 413, or any other 4xx -- retrying won't help
	ErrTransport
)

func (k ErrorKind) String() string {
	switch k {
	case ErrAuth:
		return "auth"
	case ErrRetryable:
		return "retryable"
	case ErrPermanent:
		return "permanent"
	case ErrTransport:
		return "transport"
	default:
		return "unknown"
	}
}

// Error is the typed error Client.do returns on failure.
type Error struct {
	Kind       ErrorKind
	StatusCode int
	Status     string
	Body       string
	RetryAfter time.Duration
	Err        error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("esink: %s: %v", e.Kind, e.Err)
	}
	return fmt.Sprintf("esink: %s: %s", e.Kind, e.Status)
}

func (e *Error) Unwrap() error { return e.Err }

func (e *Error) retryable() bool {
	return e.Kind == ErrRetryable || e.Kind == ErrTransport
}

func classifyStatus(code int, status string, body []byte, header http.Header) *Error {
	e := &Error{StatusCode: code, Status: status, Body: string(body)}
	switch {
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		e.Kind = ErrAuth
	case code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable:
		e.Kind = ErrRetryable
		e.RetryAfter = parseRetryAfter(header)
	case code >= 400 && code < 500:
		e.Kind = ErrPermanent
	default:
		e.Kind = ErrUnknown
	}
	return e
}

func parseRetryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// IsAuthError reports whether err is a 401/403 from Elasticsearch.
func IsAuthError(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Kind == ErrAuth
}
