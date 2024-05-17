package headers_test

import (
	"slices"
	"testing"

	"github.com/jub0bs/cors/internal/headers"
)

func TestSortedSet(t *testing.T) {
	cases := []struct {
		desc  string
		elems []string
		// expectations
		size     int
		combined string
		slice    []string
		subs     []string
		notSubs  []string
	}{
		{
			desc:     "empty set",
			size:     0,
			combined: "",
			notSubs: []string{
				",",
				"x-bar",
				"x-bar,x-foo",
			},
		}, {
			desc:     "singleton set",
			elems:    []string{"x-foo"},
			size:     1,
			combined: "x-foo",
			slice:    []string{"X-Foo"},
			subs: []string{
				"",
				"x-foo",
			},
			notSubs: []string{
				",",
				"x-foo,",
				"x-bar",
				"x-bar,x-foo",
			},
		}, {
			desc:     "no dupes",
			elems:    []string{"x-foo", "x-bar", "x-baz"},
			size:     3,
			combined: "x-bar,x-baz,x-foo",
			slice:    []string{"X-Bar", "X-Baz", "X-Foo"},
			subs: []string{
				"",
				"x-bar",
				"x-baz",
				"x-foo",
				"x-bar,x-baz",
				"x-bar,x-foo",
				"x-baz,x-foo",
				"x-bar,x-baz,x-foo",
			},
			notSubs: []string{
				",",
				"x-bar,",
				"x-baz,",
				"x-foo,",
				"x-bar,x-baz,",
				"x-bar,x-foo,",
				"x-baz,x-foo,",
				"x-bar,x-baz,x-foo,",
				"x-qux",
				"x-bar,x-baz,x-baz",
				"x-qux,x-baz",
				"x-qux,x-foo",
				"x-quxbaz,x-foo",
			},
		}, {
			desc:     "some dupes",
			elems:    []string{"x-foo", "x-bar", "x-foo"},
			size:     2,
			combined: "x-bar,x-foo",
			slice:    []string{"X-Bar", "X-Foo"},
			subs: []string{
				"",
				"x-bar",
				"x-foo",
				"x-bar,x-foo",
			},
			notSubs: []string{
				",",
				"x-bar,",
				"x-foo,",
				"x-bar,x-foo,",
				"x-qux",
				"x-qux,x-bar",
				"x-qux,x-foo",
				"x-qux,x-baz,x-foo",
			},
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			elems := slices.Clone(tc.elems)
			set := headers.NewSortedSet(tc.elems...)
			size := set.Size()
			if set.Size() != tc.size {
				const tmpl = "NewSortedSet(%#v...).Size(): got %d; want %d"
				t.Errorf(tmpl, elems, size, tc.size)
			}
			combined := set.String()
			if combined != tc.combined {
				const tmpl = "NewSortedSet(%#v...).String(): got %q; want %q"
				t.Errorf(tmpl, elems, combined, tc.combined)
			}
			slice := set.ToSortedSlice()
			if !slices.Equal(slice, tc.slice) {
				const tmpl = "NewSortedSet(%#v...).ToSortedSet(): got %q; want %q"
				t.Errorf(tmpl, elems, slice, tc.slice)
			}
			for _, sub := range tc.subs {
				if !set.Subsumes(sub) {
					const tmpl = "%q does not subsume %q, but should"
					t.Errorf(tmpl, set, sub)
				}
			}
			for _, notSub := range tc.notSubs {
				if set.Subsumes(notSub) {
					const tmpl = "%q subsumes %q, but should not"
					t.Errorf(tmpl, set, notSub)
				}
			}
		}
		t.Run(tc.desc, f)
	}
}
