package util_test

import (
	"slices"
	"testing"

	"github.com/jub0bs/cors/internal/util"
)

func TestSortedSet(t *testing.T) {
	cases := []struct {
		desc  string
		elems []string
		// expectations
		size     int
		maxLen   uint
		notElems []string
		slice    []string
	}{
		{
			desc:     "empty set",
			size:     0,
			maxLen:   0,
			notElems: []string{"x-foo"},
		}, {
			desc:     "singleton set",
			elems:    []string{"x-foo"},
			size:     1,
			maxLen:   5,
			notElems: []string{"x-bar", "x-baz", "x-qux", "x-quux"},
			slice:    []string{"x-foo"},
		}, {
			desc:     "no dupes",
			elems:    []string{"x-foo", "x-bar", "x-baz"},
			size:     3,
			maxLen:   5,
			notElems: []string{"x-qux", "x-quux"},
			slice:    []string{"x-bar", "x-baz", "x-foo"},
		}, {
			desc:     "some dupes",
			elems:    []string{"x-foo", "x-bar", "x-foo"},
			size:     2,
			maxLen:   5,
			notElems: []string{"x-baz", "x-qux", "x-quux"},
			slice:    []string{"x-bar", "x-foo"},
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			var set util.SortedSet
			for _, elem := range tc.elems {
				set.Add(elem)
			}
			size := set.Size()
			if size != tc.size {
				const tmpl = "SortedSet built from %#v: Size(): got %d; want %d"
				t.Errorf(tmpl, tc.elems, size, tc.size)
			}
			if got := set.MaxLen(); got != tc.maxLen {
				const tmpl = "SortedSet built from %#v: MaxLen(): got %d; want %d"
				t.Errorf(tmpl, tc.elems, got, tc.maxLen)
			}
			for _, e := range tc.notElems {
				for n := -1; n < size; n++ {
					const want = -1
					got := set.IndexAfter(n, e)
					if got != want {
						const tmpl = "SortedSet built from %#v: IndexAfter(%d, %q): got %d; want %d"
						t.Errorf(tmpl, tc.elems, n, e, got, want)
					}
				}
			}
			s := set.ToSlice()
			if !slices.Equal(s, tc.slice) {
				const tmpl = "SortedSet built from %#v: ToSlice(): got %q; want %q"
				t.Errorf(tmpl, tc.elems, s, tc.slice)
			}
			for pos, e := range s {
				for n := -1; n < size; n++ {
					want := pos
					if pos < n+1 {
						want = -1
					}
					got := set.IndexAfter(n, e)
					if got != want {
						const tmpl = "SortedSet built from %#v: IndexAfter(%d, %q): got %d; want %d"
						t.Errorf(tmpl, tc.elems, n, e, got, want)
					}
				}
			}
		}
		t.Run(tc.desc, f)
	}
}
