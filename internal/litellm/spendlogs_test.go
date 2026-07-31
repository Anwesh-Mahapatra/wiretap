package litellm

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// readFixture loads one captured /spend/logs/v2 response. Every fixture in
// testdata/ is a real response from a live LiteLLM 1.93.0 proxy, with two
// edits and no others: virtual-key SHA-256 hashes are remapped onto stable
// obvious fakes (distinct real hashes stay distinct, so records that shared
// a key still share one), and metadata.model_map_information -- a ~90-key
// static pricing table repeated verbatim on every record -- is dropped.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatalf("reading fixture %q: %v", name, err)
	}
	return data
}

// fixtureClient serves a fixture as the response to any request.
func fixtureClient(t *testing.T, name string) *Client {
	t.Helper()
	body := readFixture(t, name)
	return testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
}

// TestDecodeSpendLogs_RealRecords is the table-driven core of this
// package's fixture coverage: every field downstream reads, asserted
// against records LiteLLM actually produced, for each of the three
// outcomes this deployment can produce.
func TestDecodeSpendLogs_RealRecords(t *testing.T) {
	page, err := (&Client{}).decodeForTest(readFixture(t, "page_mixed"))
	if err != nil {
		t.Fatalf("decoding page_mixed: %v", err)
	}
	logs, err := DecodeSpendLogs(page.Data)
	if err != nil {
		t.Fatalf("DecodeSpendLogs: %v", err)
	}
	if len(logs) != 5 {
		t.Fatalf("expected 5 records in page_mixed, got %d", len(logs))
	}

	byClass := func(class string) []SpendLog {
		var out []SpendLog
		for _, l := range logs {
			ei := l.Metadata.ErrorInformation
			switch {
			case class == "" && ei == nil:
				out = append(out, l)
			case ei != nil && ei.ErrorClass == class:
				out = append(out, l)
			}
		}
		return out
	}

	for _, tc := range []struct {
		name string
		pick func() []SpendLog

		wantFailed        bool
		wantHasUsage      bool
		wantHasCost       bool
		wantErrorCode     string
		wantErrorClass    string
		wantRequestIDPfx  string
		wantProvider      string
		wantModelHasSlash bool
		wantAliasPresent  bool
		wantTraceIDOK     bool
	}{
		{
			name: "success",
			pick: func() []SpendLog { return byClass("") },

			wantFailed:        false,
			wantHasUsage:      true,
			wantHasCost:       true,
			wantRequestIDPfx:  "chatcmpl-",
			wantProvider:      "groq",
			wantModelHasSlash: true, // served model is provider-prefixed
			wantAliasPresent:  true,
			wantTraceIDOK:     true,
		},
		{
			name: "budget block",
			pick: func() []SpendLog { return byClass("BudgetExceededError") },

			wantFailed:     true,
			wantHasUsage:   false, // usage_object is null: absent, not zero
			wantHasCost:    false, // cost_breakdown is null
			wantErrorCode:  "429",
			wantErrorClass: "BudgetExceededError",
			// request_id on a refusal is a LiteLLM UUID, not a completion
			// ID -- which is exactly why the completion ID cannot be the
			// primary join key. See docs/CORRELATION.md.
			wantRequestIDPfx:  "",
			wantProvider:      "", // never routed, so no provider
			wantModelHasSlash: false,
			wantAliasPresent:  true, // the key exists, it is just over budget
			wantTraceIDOK:     true,
		},
		{
			name: "auth failure",
			pick: func() []SpendLog { return byClass("KeyNotFoundError") },

			wantFailed:        true,
			wantHasUsage:      false,
			wantHasCost:       false,
			wantErrorCode:     "401",
			wantErrorClass:    "KeyNotFoundError",
			wantRequestIDPfx:  "",
			wantProvider:      "",
			wantModelHasSlash: false,
			// No alias: there is no name for a key that was never valid.
			// The attempted key's hash is still recorded, which is what
			// makes credential-spray clustering possible.
			wantAliasPresent: false,
			wantTraceIDOK:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.pick()
			if len(got) == 0 {
				t.Fatalf("fixture has no %s record", tc.name)
			}
			l := got[0]

			if l.Failed() != tc.wantFailed {
				t.Errorf("Failed() = %v, want %v (status=%q)", l.Failed(), tc.wantFailed, l.Status)
			}
			if l.HasUsage() != tc.wantHasUsage {
				t.Errorf("HasUsage() = %v, want %v -- prompt_tokens reads %d either way, which is why the discriminator is usage_object", l.HasUsage(), tc.wantHasUsage, l.PromptTokens)
			}
			if l.HasCost() != tc.wantHasCost {
				t.Errorf("HasCost() = %v, want %v -- spend reads %v either way", l.HasCost(), tc.wantHasCost, l.Spend)
			}

			ei := l.Metadata.ErrorInformation
			if tc.wantErrorClass == "" {
				if ei != nil {
					t.Errorf("ErrorInformation = %+v, want nil on a success", ei)
				}
			} else {
				if ei == nil {
					t.Fatal("ErrorInformation is nil, want structured error detail")
				}
				if ei.ErrorCode != tc.wantErrorCode {
					t.Errorf("ErrorCode = %q, want %q", ei.ErrorCode, tc.wantErrorCode)
				}
				if ei.ErrorClass != tc.wantErrorClass {
					t.Errorf("ErrorClass = %q, want %q", ei.ErrorClass, tc.wantErrorClass)
				}
				if ei.ErrorMessage == "" {
					t.Error("ErrorMessage is empty, want LiteLLM's own text")
				}
			}

			if tc.wantRequestIDPfx != "" && !strings.HasPrefix(l.RequestID, tc.wantRequestIDPfx) {
				t.Errorf("RequestID = %q, want prefix %q", l.RequestID, tc.wantRequestIDPfx)
			}
			if tc.wantRequestIDPfx == "" && strings.HasPrefix(l.RequestID, "chatcmpl-") {
				t.Errorf("RequestID = %q, want a LiteLLM UUID (a refused request produced no completion)", l.RequestID)
			}

			if l.CustomLLMProvider != tc.wantProvider {
				t.Errorf("CustomLLMProvider = %q, want %q", l.CustomLLMProvider, tc.wantProvider)
			}
			if strings.Contains(l.Model, "/") != tc.wantModelHasSlash {
				t.Errorf("Model = %q; provider-prefixed = %v, want %v", l.Model, strings.Contains(l.Model, "/"), tc.wantModelHasSlash)
			}

			if (l.Metadata.UserAPIKeyAlias != "") != tc.wantAliasPresent {
				t.Errorf("UserAPIKeyAlias = %q, want present = %v", l.Metadata.UserAPIKeyAlias, tc.wantAliasPresent)
			}
			// The key hash is recorded on every record regardless -- on an
			// auth failure it is the hash of what was attempted.
			if l.APIKey == "" {
				t.Error("APIKey (the key hash) is empty; auth-failure clustering depends on it")
			}

			id, ok := l.TraceID()
			if ok != tc.wantTraceIDOK {
				t.Errorf("TraceID() ok = %v, want %v", ok, tc.wantTraceIDOK)
			}
			if ok && id == "" {
				t.Error("TraceID() returned ok with an empty id")
			}
		})
	}
}

// TestSpendLog_TraceID covers the accessor for the join key, including the
// shapes that must NOT read as a valid ID -- an empty string that a caller
// might otherwise use as a join key is the exact failure this project has
// already paid for once.
func TestSpendLog_TraceID(t *testing.T) {
	for _, tc := range []struct {
		name   string
		raw    string
		want   string
		wantOK bool
	}{
		{"present", `{"metadata":{"spend_logs_metadata":{"trace_id":"abc"}}}`, "abc", true},
		{"no spend_logs_metadata", `{"metadata":{}}`, "", false},
		{"null spend_logs_metadata", `{"metadata":{"spend_logs_metadata":null}}`, "", false},
		{"no trace_id key", `{"metadata":{"spend_logs_metadata":{"other":"x"}}}`, "", false},
		{"empty trace_id", `{"metadata":{"spend_logs_metadata":{"trace_id":""}}}`, "", false},
		{"non-string trace_id", `{"metadata":{"spend_logs_metadata":{"trace_id":123}}}`, "", false},
		{"no metadata at all", `{}`, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s SpendLog
			if err := json.Unmarshal([]byte(tc.raw), &s); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got, ok := s.TraceID()
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("TraceID() = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestSpendLogPage_HasMore pins the pagination stop condition. Driving a
// fetch loop off TotalPages looks obvious and is wrong: the server caps
// `total` at 10,000, so on a large table TotalPages understates reality
// and the loop stops early having silently fetched a prefix.
func TestSpendLogPage_HasMore(t *testing.T) {
	for _, tc := range []struct {
		name     string
		records  int
		pageSize int
		want     bool
	}{
		{"full page means maybe more", 100, 100, true},
		{"short page means done", 42, 100, false},
		{"empty page means done", 0, 100, false},
		{"exactly one full small page", 2, 2, true},
		{"zero page size never loops", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &SpendLogPage{Data: make([]json.RawMessage, tc.records), PageSize: tc.pageSize}
			if got := p.HasMore(); got != tc.want {
				t.Errorf("HasMore() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSpendLogPage_CappedTotalDoesNotStopPagination is the concrete version
// of the above: a page whose server-reported total is the 10,000 cap must
// still be walked by HasMore, not by TotalPages.
func TestSpendLogPage_CappedTotalDoesNotStopPagination(t *testing.T) {
	c := fixtureClient(t, "page_capped_total")
	page, err := c.ListSpendLogs(context.Background(), window())
	if err != nil {
		t.Fatalf("ListSpendLogs: %v", err)
	}
	if !page.TotalIsCapped {
		t.Fatal("fixture should report total_is_capped")
	}
	if page.Total != 10000 {
		t.Errorf("Total = %d, want the 10000 cap", page.Total)
	}
	// One record on a 100-size page: genuinely the last page, and HasMore
	// says so despite TotalPages claiming 100 more.
	if page.HasMore() {
		t.Error("HasMore() = true on a 1-of-100 page")
	}
	if page.TotalPages <= 1 {
		t.Fatal("fixture should claim many pages, so the two conditions visibly disagree")
	}
}

// TestListSpendLogs_WalksEveryPage exercises the loop callers are meant to
// write: increment Page while HasMore, never trust TotalPages. The server
// here serves two 2-record pages and then a short one.
func TestListSpendLogs_WalksEveryPage(t *testing.T) {
	first := readFixture(t, "page_first_of_two")
	second := readFixture(t, "page_second_of_two")

	var pagesServed int
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		pagesServed++
		switch r.URL.Query().Get("page") {
		case "1":
			w.Write(first)
		case "2":
			w.Write(second)
		default:
			w.Write([]byte(`{"data":[],"total":4,"page":3,"page_size":2,"total_pages":2}`))
		}
	})

	var all []json.RawMessage
	params := window()
	params.PageSize = 2
	for page := 1; ; page++ {
		params.Page = page
		p, err := c.ListSpendLogs(context.Background(), params)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		all = append(all, p.Data...)
		if !p.HasMore() {
			break
		}
		if page > 10 {
			t.Fatal("pagination did not terminate")
		}
	}

	if len(all) != 4 {
		t.Errorf("collected %d records across pages, want 4", len(all))
	}
	if pagesServed != 3 {
		t.Errorf("requested %d pages, want 3 (two full, one short to terminate)", pagesServed)
	}

	logs, err := DecodeSpendLogs(all)
	if err != nil {
		t.Fatalf("DecodeSpendLogs: %v", err)
	}
	seen := map[string]bool{}
	for _, l := range logs {
		if seen[l.RequestID] {
			t.Errorf("request_id %q appeared on more than one page", l.RequestID)
		}
		seen[l.RequestID] = true
	}
}

func TestListSpendLogs_EmptyPageIsNotAnError(t *testing.T) {
	c := fixtureClient(t, "page_empty")
	page, err := c.ListSpendLogs(context.Background(), window())
	if err != nil {
		t.Fatalf("ListSpendLogs: %v", err)
	}
	if len(page.Data) != 0 {
		t.Errorf("expected 0 records, got %d", len(page.Data))
	}
	if page.HasMore() {
		t.Error("HasMore() = true on an empty page")
	}
}

// TestListSpendLogsRaw_IsByteIdenticalToTheResponse is what makes the
// archive replayable: the fetch stage writes these bytes to disk, and a
// corrected mapper months later must see exactly what the API said, not
// this package's current understanding of it.
func TestListSpendLogsRaw_IsByteIdenticalToTheResponse(t *testing.T) {
	body := readFixture(t, "page_mixed")
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { w.Write(body) })

	raw, err := c.ListSpendLogsRaw(context.Background(), window())
	if err != nil {
		t.Fatalf("ListSpendLogsRaw: %v", err)
	}
	if string(raw) != string(body) {
		t.Error("raw response was modified in transit; the archive would not be a faithful record")
	}
}

// credentialScanners are the credential shapes a captured spend-log
// fixture could plausibly contain. Each returns the offending substrings
// in content, or nil if it finds none.
//
// This list is the honest scope of TestFixtures_CarryNoCredentialMaterial:
// LiteLLM emits exactly two credential-shaped things in a response body --
// SHA-256 key hashes, and its own truncated "sk-...XXXX" key suffix -- and
// the master key, which is a request header and should never appear at
// all. Anything outside these shapes is not covered, and the test says so
// rather than implying a general secret scanner.
var credentialScanners = []struct {
	name string
	find func(content string) []string
}{
	{
		// SHA-256 hex digests: the form every virtual-key hash takes.
		name: "SHA-256 key hash",
		find: func(content string) []string {
			var bad []string
			for _, h := range hex64Re.FindAllString(content, -1) {
				if !allowedHashes[h] {
					bad = append(bad, h)
				}
			}
			return bad
		},
	},
	{
		// sk- tokens. LiteLLM only ever writes its own truncated form
		// ("sk-...XK8w") into a message body; a longer one is real key
		// material that the scrubber missed.
		//
		// The previous version of this check tested whether the *file*
		// contained "sk-..." anywhere and passed if so -- which every
		// fixture does, making it vacuous: a real key sitting beside a
		// truncated one sailed through. Scanning token by token is the
		// difference between a check and the appearance of one.
		name: "sk- API key",
		find: func(content string) []string {
			var bad []string
			for _, tok := range skTokenRe.FindAllString(content, -1) {
				if truncatedSkRe.MatchString(tok) {
					continue
				}
				bad = append(bad, tok)
			}
			return bad
		},
	},
}

var (
	// hex64Re matches a bare SHA-256 hex digest.
	hex64Re = regexp.MustCompile(`[0-9a-f]{64}`)
	// skTokenRe matches any sk-prefixed token, truncated or not.
	skTokenRe = regexp.MustCompile(`sk-[A-Za-z0-9._\-]*`)
	// truncatedSkRe matches only LiteLLM's own redacted form: literally
	// "sk-", three dots, then a short suffix. Anything else is a real key.
	truncatedSkRe = regexp.MustCompile(`^sk-\.\.\.[A-Za-z0-9]{1,8}$`)

	// allowedHashes are the fakes the capture script substitutes in, plus
	// LiteLLM's model deployment ID -- a hash of model *config*, not a
	// credential.
	allowedHashes = map[string]bool{
		strings.Repeat("a", 64): true,
		strings.Repeat("b", 64): true,
		strings.Repeat("c", 64): true,
		strings.Repeat("d", 64): true,
		"9ae42a7b54fc3b24c1456cc89d2708e6659f6dd8b3cbc7360d3eb792918d71fb": true, // model_info.id
	}
)

// TestFixtures_CarryNoCredentialMaterial is a standing check on the
// testdata directory itself. Fixtures are captured from a live proxy, so
// scrubbing is a manual step, and a manual step needs a test.
//
// Scope is deliberately narrow and named: see credentialScanners. This is
// not a general secret scanner and must not be mistaken for one.
func TestFixtures_CarryNoCredentialMaterial(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("reading testdata: %v", err)
	}

	var scanned int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		scanned++
		content := string(readFixture(t, strings.TrimSuffix(e.Name(), ".json")))
		for _, s := range credentialScanners {
			for _, hit := range s.find(content) {
				t.Errorf("%s contains %s %q -- if real, the fixture was not scrubbed; if benign, allowlist it deliberately", e.Name(), s.name, hit)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned zero fixtures -- the scan is silently passing on nothing")
	}
}

// TestCredentialScanners_CatchPlantedSecrets is the test for the test.
// TestFixtures_CarryNoCredentialMaterial passes when the fixtures are
// clean, which is indistinguishable from passing because it checks
// nothing -- exactly how the previous sk- check managed to be vacuous for
// as long as it existed. Each scanner is therefore shown catching a
// planted secret, including one placed alongside a legitimately truncated
// key in the same content.
func TestCredentialScanners_CatchPlantedSecrets(t *testing.T) {
	realFixture := string(readFixture(t, "page_mixed"))

	for _, tc := range []struct {
		name    string
		content string
		scanner string
	}{
		{
			name:    "unscrubbed key hash",
			content: `{"api_key":"559cc36f83fbb8808a77f51b55ae873f8f74fe319d39b55d919986f384db15dd"}`,
			scanner: "SHA-256 key hash",
		},
		{
			name:    "full virtual key",
			content: `{"error_message":"bad key sk-1234567890abcdefGHIJKLMNOP"}`,
			scanner: "sk- API key",
		},
		{
			// The exact case the old check missed: a real key in a
			// document that also contains a properly truncated one.
			name:    "full key beside a truncated one",
			content: `{"a":"Budget exceeded Key=bob (sk-...9SfA)","b":"sk-realkeymaterial1234567890"}`,
			scanner: "sk- API key",
		},
		{
			// And the same thing planted into a genuine fixture, so the
			// regression is demonstrated against real surrounding data.
			name:    "full key planted into a real fixture",
			content: realFixture + `{"leaked":"sk-abcdefghijklmnopqrstuvwxyz"}`,
			scanner: "sk- API key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var caughtBy []string
			for _, s := range credentialScanners {
				if len(s.find(tc.content)) > 0 {
					caughtBy = append(caughtBy, s.name)
				}
			}
			if len(caughtBy) == 0 {
				t.Fatalf("no scanner caught the planted secret; the fixture check would pass on leaked material")
			}
			var found bool
			for _, c := range caughtBy {
				if c == tc.scanner {
					found = true
				}
			}
			if !found {
				t.Errorf("caught by %v, expected %q to catch it", caughtBy, tc.scanner)
			}
		})
	}
}

// TestCredentialScanners_AcceptLiteLLMsOwnTruncatedForm confirms the sk-
// scanner does not fire on the redacted suffix LiteLLM itself writes into
// enforcement messages -- those are real fixture bytes and must survive,
// or the fixtures would have to be edited away from what the API said.
func TestCredentialScanners_AcceptLiteLLMsOwnTruncatedForm(t *testing.T) {
	for _, ok := range []string{
		`Budget has been exceeded! Key=probe-budget-1 (sk-...XK8w) Current cost: 0.0001`,
		`Received API Key = sk-...Tj3w, Key Hash (Token) =...`,
	} {
		for _, s := range credentialScanners {
			if hits := s.find(ok); len(hits) > 0 {
				t.Errorf("scanner %q flagged LiteLLM's own truncated form in %q: %v", s.name, ok, hits)
			}
		}
	}
}

// decodeForTest lets fixture tests reach the envelope decoder without
// standing up an HTTP server, for the cases where the transport is not
// what is under test.
func (c *Client) decodeForTest(body []byte) (*SpendLogPage, error) {
	var raw struct {
		Data          []json.RawMessage `json:"data"`
		Total         int               `json:"total"`
		Page          int               `json:"page"`
		PageSize      int               `json:"page_size"`
		TotalPages    int               `json:"total_pages"`
		TotalIsCapped bool              `json:"total_is_capped"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	return &SpendLogPage{
		Data: raw.Data, Total: raw.Total, Page: raw.Page,
		PageSize: raw.PageSize, TotalPages: raw.TotalPages, TotalIsCapped: raw.TotalIsCapped,
	}, nil
}

// TestSpendLog_HasUsageHasCost_ExplicitNull pins a safety that is
// currently incidental rather than deliberate.
//
// HasUsage and HasCost distinguish "LiteLLM measured this" from "the NOT
// NULL column defaulted to 0". They work because UsageObject and
// CostBreakdown are map[string]any, and encoding/json decodes a JSON null
// into a nil map. Had those fields been declared json.RawMessage -- a
// completely plausible refactor, and the type the archive parser uses --
// a null would decode into the four bytes "null", which is non-nil, and
// both methods would report true for exactly the records that have no
// data. That bug was written and caught in internal/parse; this test
// exists so the same change here fails loudly instead.
func TestSpendLog_HasUsageHasCost_ExplicitNull(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"explicit null", `{"metadata":{"usage_object":null,"cost_breakdown":null}}`, false},
		{"absent", `{"metadata":{}}`, false},
		{"no metadata", `{}`, false},
		{"present and populated", `{"metadata":{"usage_object":{"total_tokens":39},"cost_breakdown":{"total_cost":0.1}}}`, true},
		// An empty object is a real, present statement -- LiteLLM said "I
		// have a usage object and it is empty" -- which is different from
		// null. Treated as present.
		{"present but empty", `{"metadata":{"usage_object":{},"cost_breakdown":{}}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s SpendLog
			if err := json.Unmarshal([]byte(tc.raw), &s); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := s.HasUsage(); got != tc.want {
				t.Errorf("HasUsage() = %v, want %v", got, tc.want)
			}
			if got := s.HasCost(); got != tc.want {
				t.Errorf("HasCost() = %v, want %v", got, tc.want)
			}
		})
	}
}
