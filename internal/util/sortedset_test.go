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
		size   int
		maxLen int
		slice  []string
	}{
		{
			desc:   "empty set",
			size:   0,
			maxLen: 0,
		}, {
			desc:   "singleton set",
			elems:  []string{"x-foo"},
			size:   1,
			maxLen: 5,
			slice:  []string{"x-foo"},
		}, {
			desc:   "no dupes",
			elems:  []string{"x-foo", "x-bar", "x-baz"},
			size:   3,
			maxLen: 5,
			slice:  []string{"x-bar", "x-baz", "x-foo"},
		}, {
			desc:   "some dupes",
			elems:  []string{"x-foo", "x-bar", "x-foo"},
			size:   2,
			maxLen: 5,
			slice:  []string{"x-bar", "x-foo"},
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
				const tmpl = "newSortedSet(%#v...).Size(): got %d; want %d"
				t.Errorf(tmpl, tc.elems, size, tc.size)
			}
			if got := set.MaxLen(); got != tc.maxLen {
				const tmpl = "newSortedSet(%#v...).MaxLen(): got %d; want %d"
				t.Errorf(tmpl, tc.elems, got, tc.maxLen)
			}
			s := set.ToSlice()
			if !slices.Equal(s, tc.slice) {
				const tmpl = "newSortedSet(%#v...).ToSlice(): got %q; want %q"
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
						const tmpl = "newSortedSet(%#v...).IndexAfter(%d, %q): got %d; want %d"
						t.Errorf(tmpl, tc.elems, n, e, got, want)
					}
				}
			}
		}
		t.Run(tc.desc, f)
	}
}
