package langfuse

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// ErrorKind classifies why a Client call failed, so callers can react
// differently to (say) an expired API key versus a rate limit instead of
// string-matching an opaque error message.
type ErrorKind int

const (
	ErrUnknown ErrorKind = iota
	ErrAuth
	ErrNotFound
	ErrRateLimited
	ErrServerError
	ErrTransport
	ErrDecode
)

func (k ErrorKind) String() string {
	switch k {
	case ErrAuth:
		return "auth"
	case ErrNotFound:
		return "not_found"
	case ErrRateLimited:
		return "rate_limited"
	case ErrServerError:
		return "server_error"
	case ErrTransport:
		return "transport"
	case ErrDecode:
		return "decode"
	default:
		return "unknown"
	}
}

// Error is the typed error every Client method returns on failure. Callers
// should use errors.As (or the Is* helpers below) to branch on Kind.
type Error struct {
	Kind       ErrorKind
	StatusCode int           // 0 for transport/decode errors, which never got a response
	Status     string        // e.g. "429 Too Many Requests"
	Body       string        // response body, for diagnostics -- never contains request secrets
	RetryAfter time.Duration // parsed from a Retry-After header, when ErrRateLimited and present
	Err        error         // underlying error for ErrTransport/ErrDecode
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("langfuse: %s: %v", e.Kind, e.Err)
	}
	return fmt.Sprintf("langfuse: %s: %s", e.Kind, e.Status)
}

func (e *Error) Unwrap() error { return e.Err }

// retryable reports whether a failure of this kind is worth retrying.
// Auth failures, not-found, and other 4xx client errors will not change
// their answer no matter how many times the same request is repeated.
func (e *Error) retryable() bool {
	switch e.Kind {
	case ErrRateLimited, ErrServerError, ErrTransport:
		return true
	default:
		return false
	}
}

func classifyStatus(code int, status string, body []byte, header http.Header) *Error {
	e := &Error{StatusCode: code, Status: status, Body: string(body)}
	switch {
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		e.Kind = ErrAuth
	case code == http.StatusNotFound:
		e.Kind = ErrNotFound
	case code == http.StatusTooManyRequests:
		e.Kind = ErrRateLimited
		e.RetryAfter = parseRetryAfter(header)
	case code >= 500:
		e.Kind = ErrServerError
	default:
		e.Kind = ErrUnknown
	}
	return e
}

// parseRetryAfter accepts both forms the header may take: a delay in
// seconds, or an HTTP-date to wait until. Returns 0 (meaning "use our own
// backoff instead") if the header is absent or unparseable, or if it names
// a date already in the past.
func parseRetryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func kindOf(err error) ErrorKind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ErrUnknown
}

// IsAuthError reports whether err is a 401/403 from the Langfuse API.
func IsAuthError(err error) bool { return kindOf(err) == ErrAuth }

// IsNotFound reports whether err is a 404 from the Langfuse API.
func IsNotFound(err error) bool { return kindOf(err) == ErrNotFound }

// IsRateLimited reports whether err is a 429 from the Langfuse API.
func IsRateLimited(err error) bool { return kindOf(err) == ErrRateLimited }

// IsTransportError reports whether err is a network-level failure (no
// response was ever received) rather than an API-level one.
func IsTransportError(err error) bool { return kindOf(err) == ErrTransport }
