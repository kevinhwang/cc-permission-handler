package walker

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func parseWord(t *testing.T, s string) *syntax.Word {
	t.Helper()
	// Wrap in echo so it parses as a command argument.
	f, err := syntax.NewParser().Parse(strings.NewReader("echo "+s), "")
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	call := f.Stmts[0].Cmd.(*syntax.CallExpr)
	return call.Args[1]
}

func TestSymtab_ResolveWord(t *testing.T) {
	st := newSymtab()
	st.vars["FOO"] = "hello"
	st.vars["BAR"] = "world"
	st.vars["DIR"] = "/tmp/build"

	tests := []struct {
		name   string
		input  string
		want   string
		wantOK bool
	}{
		{name: "plain literal", input: "literal", want: "literal", wantOK: true},
		{name: "single quoted", input: "'literal'", want: "literal", wantOK: true},
		{name: "double quoted literal", input: `"literal"`, want: "literal", wantOK: true},
		{name: "simple var", input: "$FOO", want: "hello", wantOK: true},
		{name: "braced var", input: "${FOO}", want: "hello", wantOK: true},
		{name: "var in dblquote", input: `"$FOO"`, want: "hello", wantOK: true},
		{name: "concat vars", input: `"${FOO}_${BAR}"`, want: "hello_world", wantOK: true},
		{name: "prefix and var", input: `"/path/$DIR/file"`, want: "/path//tmp/build/file", wantOK: true},
		{name: "unknown var", input: "$UNKNOWN", want: "", wantOK: false},
		{name: "mixed known unknown", input: `"$FOO/$UNKNOWN"`, want: "", wantOK: false},
		{name: "command subst", input: "$(echo hi)", want: "", wantOK: false},
		{name: "var with default", input: `"${FOO:-default}"`, want: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			word := parseWord(t, tt.input)
			got, ok := st.resolveWord(word)
			if ok != tt.wantOK {
				t.Fatalf("resolveWord(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Errorf("resolveWord(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSymtab_Scoping(t *testing.T) {
	t.Run("restoreInvalidating", func(t *testing.T) {
		st := newSymtab()
		st.vars["A"] = "original"
		st.vars["B"] = "keep"

		snap := st.snapshot()

		// Simulate modifications inside a conditional scope.
		st.vars["A"] = "changed"
		st.vars["C"] = "new"

		st.restoreInvalidating(snap)

		// A was changed → should be invalidated (removed).
		if _, ok := st.get("A"); ok {
			t.Error("A should be invalidated after restoreInvalidating")
		}
		// B was unchanged → should be preserved.
		if v, ok := st.get("B"); !ok || v != "keep" {
			t.Errorf("B = %q (ok=%v), want 'keep'", v, ok)
		}
		// C was new → should be removed.
		if _, ok := st.get("C"); ok {
			t.Error("C should not exist after restoreInvalidating")
		}
	})

	t.Run("restoreExact", func(t *testing.T) {
		st := newSymtab()
		st.vars["A"] = "original"

		snap := st.snapshot()
		st.vars["A"] = "changed"
		st.vars["B"] = "new"

		st.restoreExact(snap)

		if v, ok := st.get("A"); !ok || v != "original" {
			t.Errorf("A = %q (ok=%v), want 'original'", v, ok)
		}
		if _, ok := st.get("B"); ok {
			t.Error("B should not exist after restoreExact")
		}
	})
}
