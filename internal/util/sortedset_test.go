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
		}, {
			desc:     "regression test for https://github.com/jub0bs/cors/issues/15",
			elems:    []string{"a", "b", "c", "d", "e"},
			size:     5,
			maxLen:   1,
			notElems: []string{"f", "g", "h", "z", "x-foo"},
			slice:    []string{"a", "b", "c", "d", "e"},
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			t.Parallel()
			var set util.SortedSet
			for _, elem := range tc.elems {
				set.Add(elem)
			}
			set.Fix()
			size := set.Size()
			if size != tc.size {
				const tmpl = "SortedSet built from %#v: Size(): got %d; want %d"
				t.Errorf(tmpl, tc.elems, size, tc.size)
			}
			if got := set.MaxLen(); got != tc.maxLen {
				const tmpl = "SortedSet built from %#v: MaxLen(): got %d; want %d"
				t.Errorf(tmpl, tc.elems, got, tc.maxLen)
			}
			for _, e := range tc.elems {
				if !set.Contains(e) {
					const tmpl = "SortedSet built from %#v: Contains(%q): got false; want true"
					t.Errorf(tmpl, tc.elems, e)
				}
			}
			for _, e := range tc.notElems {
				if set.Contains(e) {
					const tmpl = "SortedSet built from %#v: Contains(%q): got true; want false"
					t.Errorf(tmpl, tc.elems, e)
				}
				for n := range uint(size + 1) {
					const want = -1
					got := set.Index(n, e)
					if got != want {
						const tmpl = "SortedSet built from %#v: Index(%d, %q): got %d; want %d"
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
				for n := range uint(size + 1) {
					want := pos
					if uint(pos) < n {
						want = -1
					}
					got := set.Index(n, e)
					if got != want {
						const tmpl = "SortedSet built from %#v: Index(%d, %q): got %d; want %d"
						t.Errorf(tmpl, tc.elems, n, e, got, want)
					}
				}
			}
		}
		t.Run(tc.desc, f)
	}
}
