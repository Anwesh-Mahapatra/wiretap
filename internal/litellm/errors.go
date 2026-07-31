package litellm

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// ErrorKind classifies why a Client call failed, so callers can react
// differently to (say) a rejected master key versus a rate limit instead of
// string-matching an opaque error message. Deliberately the same set of
// kinds as internal/langfuse's, so cmd/wiretapd can treat "this source is
// misconfigured" identically regardless of which source it came from.
type ErrorKind int

const (
	ErrUnknown ErrorKind = iota
	ErrAuth
	ErrNotFound
	ErrRateLimited
	ErrServerError
	ErrTransport
	ErrDecode
	// ErrBadRequest is a 4xx that is neither auth nor not-found -- for this
	// API, overwhelmingly a malformed date range. It exists as its own kind
	// because LiteLLM answers a missing or wrongly-formatted start_date with
	// a 400, and that is a caller bug to fix rather than a condition to
	// retry or a credential to rotate. See ListParams.
	ErrBadRequest
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
	case ErrBadRequest:
		return "bad_request"
	default:
		return "unknown"
	}
}

// Error is the typed error every Client method returns on failure. Callers
// should use errors.As (or the Is* helpers below) to branch on Kind.
//
// Note what is *not* here: the request. No field on this struct, and
// nothing in Error's message, can carry the Authorization header. The
// master key is the most sensitive value in this deployment -- it can mint
// virtual keys, read every spend record, and change proxy config -- so the
// only place it exists in this package is the one line in newRequest that
// sets the header. See TestError_NeverCarriesMasterKey.
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
		return fmt.Sprintf("litellm: %s: %v", e.Kind, e.Err)
	}
	return fmt.Sprintf("litellm: %s: %s", e.Kind, e.Status)
}

func (e *Error) Unwrap() error { return e.Err }

// retryable reports whether a failure of this kind is worth retrying. Auth
// failures, not-found, and bad requests will not change their answer no
// matter how many times the same request is repeated.
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
	case code >= 400:
		e.Kind = ErrBadRequest
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

// IsAuthError reports whether err is a 401/403 from the LiteLLM API --
// for this package, almost always a wrong or missing master key.
func IsAuthError(err error) bool { return kindOf(err) == ErrAuth }

// IsNotFound reports whether err is a 404. Worth branching on separately
// from IsAuthError: a 404 on /spend/logs/v2 means this LiteLLM build does
// not have the endpoint, not that the credential is wrong.
func IsNotFound(err error) bool { return kindOf(err) == ErrNotFound }

// IsRateLimited reports whether err is a 429 from the LiteLLM API.
func IsRateLimited(err error) bool { return kindOf(err) == ErrRateLimited }

// IsTransportError reports whether err is a network-level failure (no
// response was ever received) rather than an API-level one.
func IsTransportError(err error) bool { return kindOf(err) == ErrTransport }

// IsBadRequest reports whether err is a 4xx that is neither auth nor
// not-found -- see ErrBadRequest.
func IsBadRequest(err error) bool { return kindOf(err) == ErrBadRequest }
