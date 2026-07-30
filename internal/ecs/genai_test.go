package ecs

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const referenceDocPath = "../../docs/reference/ecs-gen_ai.md"

// genAIFieldSpec is one gen_ai.* field this mapper can emit, as derived
// directly from the genAI struct tree.
type genAIFieldSpec struct {
	name string       // full dotted name, e.g. "gen_ai.usage.input_tokens"
	kind reflect.Kind // the Go field's kind, pointers already unwrapped
}

// genAIFieldSpecs walks genAI (and every struct it points to) via
// reflection and returns one genAIFieldSpec per leaf JSON field, with the
// "gen_ai." prefix and dotted nesting reconstructed from the walk path.
//
// This exists so there is exactly one place that knows what fields the
// mapper emits: the genAI struct definition itself. A hand-written list
// of field names next to it would be the same drift risk this test exists
// to eliminate, just moved one file over.
func genAIFieldSpecs(t *testing.T) []genAIFieldSpec {
	t.Helper()
	var out []genAIFieldSpec
	var walk func(rt reflect.Type, prefix string)
	walk = func(rt reflect.Type, prefix string) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			tag := f.Tag.Get("json")
			name, _, _ := strings.Cut(tag, ",")
			if name == "" || name == "-" {
				continue
			}
			full := prefix + name

			ft := f.Type
			for ft.Kind() == reflect.Ptr {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				walk(ft, full+".")
				continue
			}
			if ft.Kind() == reflect.Slice {
				out = append(out, genAIFieldSpec{name: "gen_ai." + full, kind: ft.Elem().Kind()})
				continue
			}
			out = append(out, genAIFieldSpec{name: "gen_ai." + full, kind: ft.Kind()})
		}
	}
	walk(reflect.TypeOf(genAI{}), "")
	if len(out) == 0 {
		t.Fatal("genAIFieldSpecs found zero fields -- the reflection walk is broken, not that genAI has no fields")
	}
	return out
}

// docFieldTypeRe matches one field's markdown-table row far enough to
// capture its stated ECS type. docs/reference/ecs-gen_ai.md renders each
// field as "[gen_ai.foo.bar](#anchor) | ...description....type:
// KEYWORDexample: ..." -- note there is no space or punctuation between
// the type word and the literal "example" that follows it in the source
// document, so the word boundary has to be anchored on "example" rather
// than on whitespace.
var docFieldTypeRe = regexp.MustCompile(`type:\s*([a-z]+)example`)

// ecsTypeCompatibleKinds maps each ECS field type this project's mapper
// might plausibly emit to the Go reflect.Kind(s) considered compatible
// with it. Extend this if a future field uses an ECS type not listed here
// -- TestGenAIFieldsExistInReferenceDoc fails loudly, naming the field, if
// it hits one that isn't.
var ecsTypeCompatibleKinds = map[string][]reflect.Kind{
	"keyword": {reflect.String},
	"text":    {reflect.String},
	"integer": {reflect.Int, reflect.Int32, reflect.Int64},
	"long":    {reflect.Int, reflect.Int32, reflect.Int64},
	"double":  {reflect.Float32, reflect.Float64},
	"float":   {reflect.Float32, reflect.Float64},
	"boolean": {reflect.Bool},
	"nested":  {reflect.String}, // arrays of keyword values, per the doc's own examples (e.g. ["stop","length"])
}

// TestGenAIFieldsExistInReferenceDoc is the executable replacement for the
// line-number citations internal/ecs/genai.go used to carry. It reads
// docs/reference/ecs-gen_ai.md fresh at test time, so editing that file --
// which previously broke every citation silently, see genai.go's package
// doc -- now fails this test instead, with a message naming exactly which
// field and what's wrong.
func TestGenAIFieldsExistInReferenceDoc(t *testing.T) {
	doc, err := os.ReadFile(referenceDocPath)
	if err != nil {
		t.Fatalf("reading reference doc %q: %v (has it moved? update referenceDocPath if so)", referenceDocPath, err)
	}
	content := string(doc)

	for _, field := range genAIFieldSpecs(t) {
		t.Run(field.name, func(t *testing.T) {
			link := "[" + field.name + "]"
			idx := strings.Index(content, link)
			if idx == -1 {
				t.Fatalf("field %q does not appear in %s -- either this field was invented rather than taken from the doc, or the doc's own field name/anchor format changed. Do not add a gen_ai.* field that isn't in this file.", field.name, referenceDocPath)
			}

			// The type declaration is later in the same table row --
			// bound the search to one line so a later field's type can
			// never be mistaken for this one's.
			lineEnd := strings.IndexByte(content[idx:], '\n')
			if lineEnd == -1 {
				lineEnd = len(content) - idx
			}
			row := content[idx : idx+lineEnd]

			m := docFieldTypeRe.FindStringSubmatch(row)
			if m == nil {
				t.Fatalf("field %q was found in %s but its row doesn't match the expected \"type: X example\" pattern -- the doc's format may have changed; update docFieldTypeRe", field.name, referenceDocPath)
			}
			docType := m[1]

			compatible, known := ecsTypeCompatibleKinds[docType]
			if !known {
				t.Fatalf("field %q has ECS type %q, which TestGenAIFieldsExistInReferenceDoc has no compatibility rule for -- add one to ecsTypeCompatibleKinds instead of assuming it's fine", field.name, docType)
			}
			for _, k := range compatible {
				if field.kind == k {
					return // compatible; test passes
				}
			}
			t.Fatalf("field %q is Go kind %s, but the reference doc declares it ECS type %q (expected Go kind one of %v) -- the mapper's Go type does not match the schema", field.name, field.kind, docType, compatible)
		})
	}
}
