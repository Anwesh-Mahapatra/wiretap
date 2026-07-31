package ecs

import "wiretap/internal/model"

// DefaultGatewayConfig returns the Config for mapping this project's
// LiteLLM gateway plane.
//
// LangfuseBaseURL is empty because a spend record has no UI to link back
// to -- LiteLLM's admin console has no per-request page -- so
// event.reference is left absent rather than pointed somewhere that
// 404s.
func DefaultGatewayConfig() Config {
	return Config{
		GenAISystemFallback:    DefaultGenAISystem,
		GenAIOperationFallback: DefaultGenAIOperation,
	}
}

// MapGateway builds an ECS Document for the *gateway* plane (event.dataset
// "wiretap.litellm") from ev, which must carry a GatewayDetail.
//
// It shares newDocument with Map, so @timestamp, event.start/end,
// trace.id, ecs.version and event.* core are constructed once and mean the
// same thing in both datasets -- which is the precondition for a
// correlation query spanning them. What it adds is everything only a
// gateway knows: the HTTP status the caller received, the machine-readable
// class of refusal, and which credential paid.
//
// Like Map it is a pure function, for the same golden-file reason.
//
// Fields deliberately NOT set here, and why:
//
//   - llm.user_prompt, llm.output, llm.messages. The gateway never sees
//     content; in this deployment its records carry an empty messages and
//     response field by construction. Emitting empty strings would make
//     "NOT llm.output: *" silently mean "or it is a gateway document".
//   - llm.generation_count. A spend record is one HTTP attempt, not a
//     count of generations. Reporting 1 would invite summing it across
//     datasets as though it were the same measure.
//   - event.reference. See DefaultGatewayConfig.
func MapGateway(ev *model.LLMEvent, cfg Config) *Document {
	doc := newDocument(ev, DatasetLiteLLM)

	gw := ev.Gateway
	if gw == nil {
		// A gateway document without gateway detail would be a content
		// document wearing the wrong dataset label. Return what we have
		// rather than inventing fields; the caller's parser is what
		// guarantees this is non-nil in practice.
		return doc
	}

	doc.Event.Type = gatewayEventTypes(ev, gw)
	doc.Event.Category = gatewayEventCategories(gw)
	doc.Event.Action = gatewayAction(ev, gw)

	if gw.HTTPStatusCode != nil {
		code := *gw.HTTPStatusCode
		doc.HTTP = &ecsHTTP{Response: &ecsHTTPResponse{StatusCode: &code}}
	}

	// error.type and error.code are the gateway's headline contribution.
	// newDocument already set error.message from ev.StatusMessage if the
	// source reported one; a refusal may carry a class without a message,
	// so the object is created here if it does not exist yet.
	if gw.ErrorClass != "" || gw.ErrorCode != "" {
		if doc.Error == nil {
			doc.Error = &ecsError{}
		}
		doc.Error.Type = gw.ErrorClass
		doc.Error.Code = gw.ErrorCode
	}

	doc.LLM = llm{
		TotalCostUSD: ev.TotalCost,
	}
	if gw.KeyAlias != "" || gw.KeyHash != "" {
		doc.LLM.Key = &llmKey{Alias: gw.KeyAlias, Hash: gw.KeyHash}
	}

	if users := relatedUsers(ev, gw); len(users) > 0 {
		doc.Related = &related{User: users}
	}

	doc.GenAI = buildGenAI(ev, cfg)

	return doc
}

// gatewayEventTypes maps outcome onto ECS's categorization vocabulary.
// "allowed" and "denied" are documented allowed values for event.type and
// are both expected types for the "api" category.
//
// An authentication failure additionally carries "start", because ECS's
// "authentication" category expects start/end/info -- see
// categoryAuthentication. A rejected credential *is* the start of a
// challenge-and-response exchange; that it did not complete is carried by
// event.outcome, not by omitting the type.
//
// StatusUnknown yields no event.type at all. "We could not tell" is not
// "allowed", and defaulting to either would put a categorization value on
// an event that does not support it.
func gatewayEventTypes(ev *model.LLMEvent, gw *model.GatewayDetail) []string {
	switch ev.Status {
	case model.StatusSuccess:
		return []string{typeAllowed}
	case model.StatusFailure:
		if isAuthFailure(gw) {
			return []string{typeDenied, typeStart}
		}
		return []string{typeDenied}
	default:
		return nil
	}
}

// gatewayEventCategories returns ["api"] for every gateway event, plus
// "authentication" for a credential rejection.
//
// The missing "authentication" is the reason this function exists rather
// than a constant. event.category was ["api"] and only ["api"] for every
// document this project has ever indexed -- not a wrong value, an
// *incomplete* one. A detection filtering event.category: "authentication"
// returned zero hits, and zero hits reads exactly like "no authentication
// failures occurred". See notes.md.
func gatewayEventCategories(gw *model.GatewayDetail) []string {
	if isAuthFailure(gw) {
		return []string{categoryAPI, categoryAuthentication}
	}
	return []string{categoryAPI}
}

// authErrorClasses are the LiteLLM exception classes that mean "the
// credential was rejected", as opposed to "the credential was fine but the
// request was refused for another reason" (budget, rate limit).
//
// Keyed on error class rather than on HTTP status because status is not
// sufficient: LiteLLM answers a budget block AND a rate limit with 429,
// and both are refusals that have nothing to do with authentication.
// Status 401/403 is checked too, as a second signal for a class this table
// has not been updated for.
var authErrorClasses = map[string]bool{
	"KeyNotFoundError":    true,
	"AuthenticationError": true,
	"ProxyAuthError":      true,
	"InvalidAPIKeyError":  true,
	"ExpiredKeyError":     true,
}

func isAuthFailure(gw *model.GatewayDetail) bool {
	if authErrorClasses[gw.ErrorClass] {
		return true
	}
	if gw.HTTPStatusCode != nil {
		switch *gw.HTTPStatusCode {
		case 401, 403:
			return true
		}
	}
	return false
}

// gatewayAction fills event.action -- ECS's "more specific than
// event.category" field. Free-form by ECS's own definition, so this uses a
// small closed vocabulary derived from the error class rather than passing
// the class through raw: error.type already carries the class verbatim,
// and event.action is meant to be the stable, groupable thing a rule
// pivots on.
//
// Deriving from error class rather than status code matters for the same
// reason as everywhere else here: budget_exceeded and rate_limited are
// both 429.
func gatewayAction(ev *model.LLMEvent, gw *model.GatewayDetail) string {
	if ev.Status != model.StatusFailure {
		return actionChatCompletion
	}
	switch {
	case gw.ErrorClass == "BudgetExceededError":
		return actionBudgetExceeded
	case gw.ErrorClass == "ProxyRateLimitError" || gw.ErrorClass == "RateLimitError":
		return actionRateLimited
	case isAuthFailure(gw):
		return actionAuthFailure
	case gw.ErrorClass != "":
		return actionRequestFailed
	default:
		return actionRequestFailed
	}
}

// event.action vocabulary. Closed on purpose: a rule that groups by
// event.action should not have to cope with a new string every time
// LiteLLM adds an exception class. Anything unrecognised becomes
// request_failed, and error.type still carries the exact class for
// whoever is investigating.
const (
	actionChatCompletion = "chat_completion"
	actionBudgetExceeded = "budget_exceeded"
	actionRateLimited    = "rate_limited"
	actionAuthFailure    = "auth_failure"
	actionRequestFailed  = "request_failed"
)

// relatedUsers collects every identifier for "who or what made this
// request" into ECS's related.user, so one pivot query finds a request
// whether the analyst is holding an end-user ID or a key alias. They stay
// mapped to their own distinct fields as well (user.id and llm.key.alias);
// this is an additional index, not a replacement.
func relatedUsers(ev *model.LLMEvent, gw *model.GatewayDetail) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range []string{ev.UserID, gw.KeyAlias} {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
