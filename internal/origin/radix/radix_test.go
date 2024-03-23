package radix_test

import (
	"testing"

	"github.com/jub0bs/cors/internal/origin/radix"
)

type TestCase struct {
	desc     string
	patterns []Pair
	accept   []Pair
	reject   []Pair
}

type Pair struct {
	key   string
	value int
}

func TestRadix(t *testing.T) {
	cases := []TestCase{
		{
			desc: "empty tree",
			reject: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"kin", 0},
				{"pin", 0},
			},
		}, {
			desc: "single empty pattern",
			patterns: []Pair{
				{"", 0},
			},
			accept: []Pair{
				{"", 0},
			},
			reject: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"kin", 0},
				{"pin", 0},
			},
		}, {
			desc: "wildcard-free patterns",
			patterns: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"kin", 0},
				{"pin", 0},
			},
			accept: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"kin", 0},
				{"pin", 0},
			},
			reject: []Pair{
				{"", 0},
				// different value
				{"cat", 1},
				{"concat", 1},
				{"kin", 1},
				{"pin", 1},
				// truncated key (at the end), same value
				{"ca", 0},
				{"con", 0},
				{"ki", 0},
				{"p", 0},
				// truncated key (at the start), same value
				{"at", 0},
				{"ncat", 0},
				{"in", 0},
				{"n", 0},
				// extended key, same value
				{"copycat", 0},
				{"string_concat", 0},
				{"akin", 0},
				{"bespin", 0},
			},
		}, {
			desc: "duplicate patterns",
			patterns: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"kin", 0},
				{"pin", 0},
				{"cat", 0},
				{"concat", 0},
				{"kin", 0},
				{"pin", 0},
			},
			accept: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"kin", 0},
				{"pin", 0},
			},
			reject: []Pair{
				{"", 0},
				// different value
				{"cat", 1},
				{"concat", 1},
				{"kin", 1},
				{"pin", 1},
				// truncated key (at the end), same value
				{"ca", 0},
				{"con", 0},
				{"ki", 0},
				{"p", 0},
				// truncated key (at the start), same value
				{"at", 0},
				{"ncat", 0},
				{"in", 0},
				{"n", 0},
				// extended key, same value
				{"copycat", 0},
				{"string_concat", 0},
				{"akin", 0},
				{"bespin", 0},
			},
		}, {
			desc: "wildcard-free patterns with multiple values",
			patterns: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"kin", 0},
				{"pin", 0},
				{"cat", 1},
				{"concat", 1},
				{"kin", 1},
				{"pin", 1},
			},
			accept: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"kin", 0},
				{"pin", 0},
				{"cat", 1},
				{"concat", 1},
				{"kin", 1},
				{"pin", 1},
			},
			reject: []Pair{
				{"", 0},
				// different value
				{"cat", 2},
				{"concat", 2},
				{"kin", 2},
				{"pin", 2},
				// truncated key (at the end), same value
				{"ca", 0},
				{"con", 0},
				{"ki", 0},
				{"p", 0},
				{"ca", 1},
				{"con", 1},
				{"ki", 1},
				{"p", 1},
				// truncated key (at the start), same value
				{"at", 0},
				{"ncat", 0},
				{"in", 0},
				{"n", 1},
				{"at", 1},
				{"ncat", 1},
				{"in", 1},
				{"n", 1},
				// extended key, same value
				{"copycat", 0},
				{"string_concat", 0},
				{"akin", 0},
				{"bespin", 0},
				{"copycat", 1},
				{"string_concat", 1},
				{"akin", 1},
				{"bespin", 1},
			},
		}, {
			desc: "wildcard-free patterns in reverse insertion order",
			patterns: []Pair{
				{"pin", 0},
				{"kin", 0},
				{"concat", 0},
				{"cat", 0},
			},
			accept: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"kin", 0},
				{"pin", 0},
			},
			reject: []Pair{
				{"", 0},
				// different value
				{"cat", 1},
				{"concat", 1},
				{"kin", 1},
				{"pin", 1},
				// truncated key (at the end), same value
				{"ca", 0},
				{"con", 0},
				{"ki", 0},
				{"p", 0},
				// truncated key (at the start), same value
				{"at", 0},
				{"attle", 0},
				{"in", 0},
				{"n", 0},
				// extended key, same value
				{"copycat", 0},
				{"string_concat", 0},
				{"akin", 0},
				{"bespin", 0},
			},
		}, {
			desc: "some wildcard-full patterns",
			patterns: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"*kin", 0},
				{"akin", 0},
				{"*kin", 1},
				{"pin", 0},
			},
			accept: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"akin", 0},
				{"pin", 0},
				// extended key, same value
				{"napkin", 0},
				{"napkin", 1},
			},
			reject: []Pair{
				{"", 0},
				{"cat", 1},
				{"concat", 1},
				{"kin", 1},
				{"pin", 1},
				// truncated key (at the end), same value
				{"ca", 0},
				{"conca", 0},
				{"ki", 0},
				{"p", 0},
				// truncated key (at the start), same value
				{"at", 0},
				{"ncat", 0},
				{"in", 0},
				{"n", 0},
				// extended key, same value
				{"copycat", 0},
				{"string_concat", 0},
				{"bespin", 0},
				// extended key, different value
				{"napkin", 2},
				{"napkin", 3},
			},
		}, {
			desc: "patterns containing a non-trailing asterisk",
			patterns: []Pair{
				{"*k*n", 0},
				{"pin", 0},
			},
			accept: []Pair{
				{"ak*n", 0},
				{"napk*n", 0},
				{"pin", 0},
			},
			reject: []Pair{
				{"", 0},
				{"kin", 0},
				{"akin", 0},
				{"k*n", 0},
				{"pin", 1},
			},
		}, {
			desc: "wildcard-free patterns and wildcard value",
			patterns: []Pair{
				{"cat", -1},
				{"cat", 0},
				{"concat", -1},
				{"kin", 0},
				{"pin", 0},
			},
			accept: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"cat", 1},
				{"concat", 1},
				{"kin", 0},
				{"pin", 0},
			},
			reject: []Pair{
				{"", 0},
				// different value
				{"kin", 1},
				{"pin", 1},
				// truncated key (at the end), same value
				{"ca", 0},
				{"con", 0},
				{"ki", 0},
				{"p", 0},
				// truncated key (at the start), same value
				{"at", 0},
				{"ncat", 0},
				{"in", 0},
				{"n", 0},
				// extended key, same value
				{"copycat", 0},
				{"string_concat", 0},
				{"akin", 0},
				{"bespin", 0},
			},
		}, {
			desc: "some wildcard-full patterns and wildcard value",
			patterns: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"*kin", -1},
				{"*kin", 0},
				{"pin", 0},
			},
			accept: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"pin", 0},
				// extended key, arbitrary value
				{"napkin", -1},
				{"napkin", 0},
				{"napkin", 1},
			},
			reject: []Pair{
				{"", 0},
				// different value
				{"cat", 1},
				{"concat", 1},
				{"kin", 1},
				{"pin", 1},
				// truncated key (at the end), same value
				{"ca", 0},
				{"con", 0},
				{"ki", 0},
				{"p", 0},
				// truncated key (at the start), same value
				{"at", 0},
				{"ncat", 0},
				{"in", 0},
				{"n", 0},
				// extended key, same value
				{"copycat", 0},
				{"string_concat", 0},
				{"bespin", 0},
			},
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			var tree radix.Tree
			for _, pair := range tc.patterns {
				tree.Insert(pair.key, pair.value)
			}
			var (
				topHeader    bool
				acceptHeader bool
			)
			for _, pair := range tc.accept {
				if !tree.Contains(pair.key, pair.value) {
					if !topHeader {
						logMsgHeader(t, tc.patterns)
						topHeader = true
					}
					if !acceptHeader {
						t.Log("does not (but should) contain")
						acceptHeader = true
					}
					t.Errorf("\t- %v\n", pair)
				}
			}
			var rejectHeader bool
			for _, pair := range tc.reject {
				if tree.Contains(pair.key, pair.value) {
					if !topHeader {
						logMsgHeader(t, tc.patterns)
						topHeader = true
					}
					if !rejectHeader {
						t.Log("does (but should not) contain")
						rejectHeader = true
					}
					t.Errorf("\t- %v\n", pair)
				}
			}
		}
		t.Run(tc.desc, f)
	}
}

func logMsgHeader(t *testing.T, pairs []Pair) {
	t.Helper()
	t.Log("a radix tree composed of")
	for _, pair := range pairs {
		t.Logf("\t- %v\n", pair)
	}
}
