package origins

import (
	"math"
	"slices"
	"testing"
)

var ( // compile-time checks
	_ [wildcardPort - 1 - math.MaxUint16]struct{} // wildcardPort > math.MaxUint16
	_ [math.MaxInt - wildcardPort]struct{}        // wildcardPort <= math.MaxInt
	_ [portOffset - 1 - wildcardPort]struct{}     // portOffset > wildcardPort
	_ [-(math.MinInt + portOffset)]struct{}       // portOffset >= math.MinInt
)

func TestRadix(t *testing.T) {
	type Pair struct {
		key   string
		value int
	}
	type TestCase struct {
		desc     string
		patterns []Pair
		elems    []string
		accept   []Pair
		reject   []Pair
	}
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
			elems: []string{""},
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
			elems: []string{
				"cat",
				"concat",
				"kin",
				"pin",
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
				// regression tests for GHSA-vhxv-fg4m-p2w8
				{"pkin", 0},
				{"kpin", 0},
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
			elems: []string{
				"cat",
				"concat",
				"kin",
				"pin",
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
				// regression tests for GHSA-vhxv-fg4m-p2w8
				{"pkin", 0},
				{"kpin", 0},
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
			elems: []string{
				"cat",
				"cat:1",
				"concat",
				"concat:1",
				"kin",
				"kin:1",
				"pin",
				"pin:1",
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
				// regression tests for GHSA-vhxv-fg4m-p2w8
				{"pkin", 0},
				{"kpin", 0},
				{"pkin", 1},
				{"kpin", 1},
			},
		}, {
			desc: "wildcard-free patterns in reverse insertion order",
			patterns: []Pair{
				{"pin", 0},
				{"kin", 0},
				{"concat", 0},
				{"cat", 0},
			},
			elems: []string{
				"cat",
				"concat",
				"kin",
				"pin",
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
				// regression tests for GHSA-vhxv-fg4m-p2w8
				{"kpin", 0},
				{"pkin", 0},
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
			elems: []string{
				"*kin",
				"*kin:1",
				"cat",
				"concat",
				"pin",
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
			elems: []string{
				"*k*n",
				"pin",
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
				{"cat", 1 << 16},
				{"cat", 0},
				{"concat", 1 << 16},
				{"kin", 0},
				{"pin", 0},
			},
			elems: []string{
				"cat:*",
				"concat:*",
				"kin",
				"pin",
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
				// regression tests for GHSA-vhxv-fg4m-p2w8
				{"pkin", 0},
				{"kpin", 0},
			},
		}, {
			desc: "some wildcard-full patterns and wildcard value",
			patterns: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"*kin", 1 << 16},
				{"*kin", 0},
				{"pin", 0},
			},
			elems: []string{
				"*kin:*",
				"cat",
				"concat",
				"pin",
			},
			accept: []Pair{
				{"cat", 0},
				{"concat", 0},
				{"pin", 0},
				// extended key, arbitrary value
				{"napkin", 1 << 16},
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
			var tree Tree
			for _, pair := range tc.patterns {
				tree.Insert(pair.key, pair.value)
			}
			var elems []string
			tree.Elems(&elems, "")
			slices.Sort(elems)
			if !slices.Equal(elems, tc.elems) {
				t.Errorf("got %q; want %q", elems, tc.elems)
			}
			var (
				topHeader    bool
				acceptHeader bool
			)
			for _, pair := range tc.accept {
				if !tree.Contains(pair.key, pair.value) {
					if !topHeader {
						t.Log("a radix tree composed of")
						for _, pair := range tc.patterns {
							t.Logf("\t- %v\n", pair)
						}
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
						t.Log("a radix tree composed of")
						for _, pair := range tc.patterns {
							t.Logf("\t- %v\n", pair)
						}
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
