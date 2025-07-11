package headers_test

import (
	"strings"
	"testing"

	"github.com/jub0bs/cors/internal/headers"
	"github.com/jub0bs/cors/internal/util"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		desc     string
		elems    []string
		accepted [][]string
		rejected [][]string
	}{
		{
			desc: "empty set",
			accepted: [][]string{
				// some empty elements, possibly with OWS
				{""},
				{","},
				{"\t, , "},
				// multiple field lines, some empty elements
				make([]string, headers.MaxEmptyElements),
			},
			rejected: [][]string{
				{"x-bar"},
				{"x-bar,x-foo"},
				// too many empty elements
				{strings.Repeat(",", headers.MaxEmptyElements+1)},
				// multiple field lines, too many empty elements
				make([]string, headers.MaxEmptyElements+1),
			},
		}, {
			desc:  "singleton set",
			elems: []string{"x-foo"},
			accepted: [][]string{
				{"x-foo"},
				// some OWS
				{" x-foo "},
				{"  x-foo"},
				{"x-foo  "},
				// some empty elements, possibly with OWS
				{""},
				{","},
				{"\t, , "},
				{"\tx-foo ,"},
				{" x-foo\t,"},
				{strings.Repeat(",", headers.MaxEmptyElements) + "x-foo"},
				// multiple field lines, some empty elements
				append(make([]string, headers.MaxEmptyElements), "x-foo"),
				make([]string, headers.MaxEmptyElements),
			},
			rejected: [][]string{
				{"x-bar"},
				{"x-bar,x-foo"},
				// too much OWS
				{"x-foo   "},
				{" x-foo  "},
				{"  x-foo "},
				{" x-foo\t\t"},
				{"\tx-foo\t\t"},
				{"\t\tx-foo\t\t"},
				// too many empty elements
				{strings.Repeat(",", headers.MaxEmptyElements+1) + "x-foo"},
				// multiple field lines, too many empty elements
				append(make([]string, headers.MaxEmptyElements+1), "x-foo"),
				make([]string, headers.MaxEmptyElements+1),
			},
		}, {
			desc:  "no dupes",
			elems: []string{"x-foo", "x-bar", "x-baz"},
			accepted: [][]string{
				{"x-bar"},
				{"x-baz"},
				{"x-foo"},
				{"x-bar,x-baz"},
				{"x-bar,x-foo"},
				{"x-baz,x-foo"},
				{"x-bar,x-baz,x-foo"},
				// some empty elements, possibly with OWS
				{""},
				{","},
				{"\t, , "},
				{"\tx-bar ,"},
				{" x-baz\t,"},
				{"x-foo,"},
				{"\tx-bar ,\tx-baz ,"},
				{" x-bar\t, x-foo\t,"},
				{"x-baz,x-foo,"},
				{" x-bar , x-baz , x-foo ,"},
				{"x-bar" + strings.Repeat(",", headers.MaxEmptyElements+1) + "x-foo"},
				// multiple field lines
				{"x-bar", "x-foo"},
				{"x-bar", "x-baz,x-foo"},
				// multiple field lines, some empty elements
				append(make([]string, headers.MaxEmptyElements), "x-bar", "x-foo"),
				make([]string, headers.MaxEmptyElements),
			},
			rejected: [][]string{
				{"x-qux"},
				{"x-bar,x-baz,x-baz"},
				{"x-qux,x-baz"},
				{"x-qux,x-foo"},
				{"x-quxbaz,x-foo"},
				// too much OWS
				{" x-bar  "},
				{"  x-baz "},
				{"   x-foo"},
				{" x-bar\t\t,x-baz"},
				{"x-bar,\tx-foo\t\t"},
				{"\t\tx-baz, x-foo\t\t"},
				{" x-bar\t,\tx-baz\t ,x-foo"},
				// too many empty elements
				{"x-bar" + strings.Repeat(",", headers.MaxEmptyElements+2) + "x-foo"},
				// multiple field lines, elements in the wrong order
				{"x-foo", "x-bar"},
				// multiple field lines, too many empty elements
				append(make([]string, headers.MaxEmptyElements+1), "x-bar", "x-foo"),
				make([]string, headers.MaxEmptyElements+1),
			},
		}, {
			desc:  "some dupes",
			elems: []string{"x-foo", "x-bar", "x-foo"},
			accepted: [][]string{
				{"x-bar"},
				{"x-foo"},
				{"x-bar,x-foo"},
				// some empty elements, possibly with OWS
				{""},
				{","},
				{"\t, , "},
				{"\tx-bar ,"},
				{" x-foo\t,"},
				{"x-foo,"},
				{"\tx-bar ,\tx-foo ,"},
				{" x-bar\t, x-foo\t,"},
				{"x-bar,x-foo,"},
				{" x-bar , x-foo ,"},
				{"x-bar" + strings.Repeat(",", headers.MaxEmptyElements+1) + "x-foo"},
				// multiple field lines
				{"x-bar", "x-foo"},
				// multiple field lines, some empty elements
				append(make([]string, headers.MaxEmptyElements), "x-bar", "x-foo"),
				make([]string, headers.MaxEmptyElements),
			},
			rejected: [][]string{
				{"x-qux"},
				{"x-qux,x-bar"},
				{"x-qux,x-foo"},
				{"x-qux,x-baz,x-foo"},
				// too much OWS
				{"x-qux  "},
				{"x-qux,\t\tx-bar"},
				{"x-qux,x-foo\t\t"},
				{"\tx-qux , x-baz\t\t,x-foo"},
				// too many empty elements
				{"x-bar" + strings.Repeat(",", headers.MaxEmptyElements+2) + "x-foo"},
				// multiple field lines, elements in the wrong order
				{"x-foo", "x-bar"},
				// multiple field lines, too much whitespace
				{"x-qux", "\t\tx-bar"},
				{"x-qux", "x-foo\t\t"},
				{"\tx-qux ", " x-baz\t\t,x-foo"},
				// multiple field lines, too many empty elements
				append(make([]string, headers.MaxEmptyElements+1), "x-bar", "x-foo"),
				make([]string, headers.MaxEmptyElements+1),
			},
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			var set util.SortedSet
			for _, elem := range tc.elems {
				set.Add(elem)
			}
			slice := set.ToSlice()
			for _, a := range tc.accepted {
				if !headers.Check(set, a) {
					const tmpl = "%q rejects %q, but should accept it"
					t.Errorf(tmpl, slice, a)
				}
			}
			for _, r := range tc.rejected {
				if headers.Check(set, r) {
					const tmpl = "%q accepts %q, but should reject it"
					t.Errorf(tmpl, slice, r)
				}
			}
		}
		t.Run(tc.desc, f)
	}
}
