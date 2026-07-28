package parse

import "fmt"

// excerptLen caps how much of a bad line ends up in an error message --
// enough to recognize the record, not so much that one huge line floods
// the log.
const excerptLen = 200

// LineError is returned by ParseLine when a line can't be decoded at all.
// It carries which line and what it looked like, because "invalid JSON"
// with no other context is not debuggable against a multi-megabyte archive
// at 3am.
type LineError struct {
	Line    int
	Excerpt string
	Err     error
}

func (e *LineError) Error() string {
	return fmt.Sprintf("parse: line %d: %v (near %q)", e.Line, e.Err, e.Excerpt)
}

func (e *LineError) Unwrap() error { return e.Err }

func newLineError(lineNo int, raw []byte, err error) *LineError {
	excerpt := string(raw)
	if len(excerpt) > excerptLen {
		excerpt = excerpt[:excerptLen] + "..."
	}
	return &LineError{Line: lineNo, Excerpt: excerpt, Err: err}
}
