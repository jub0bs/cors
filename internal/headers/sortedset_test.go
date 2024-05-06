package headers_test

import (
	"slices"
	"testing"

	"github.com/jub0bs/cors/internal/headers"
)

func TestSortedSet(t *testing.T) {
	cases := []struct {
		desc     string
		elems    []string
		combined string
		subs     []string
		notSubs  []string
		// expectations
		size  int
		slice []string
	}{
		{
			desc:     "empty set",
			combined: "",
			notSubs: []string{
				"x-bar",
				"x-bar,x-foo",
			},
			size: 0,
		}, {
			desc:     "singleton set",
			elems:    []string{"x-foo"},
			combined: "x-foo",
			subs: []string{
				"",
				"x-foo",
			},
			notSubs: []string{
				"x-bar",
				"x-bar,x-foo",
			},
			size:  1,
			slice: []string{"X-Foo"},
		}, {
			desc:     "no dupes",
			elems:    []string{"x-foo", "x-bar", "x-baz"},
			combined: "x-bar,x-baz,x-foo",
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
				"x-qux",
				"x-bar,x-baz,x-baz",
				"x-qux,x-baz",
				"x-qux,x-foo",
				"x-quxbaz,x-foo",
			},
			size:  3,
			slice: []string{"X-Bar", "X-Baz", "X-Foo"},
		}, {
			desc:     "some dupes",
			elems:    []string{"x-foo", "x-bar", "x-foo"},
			combined: "x-bar,x-foo",
			subs: []string{
				"",
				"x-bar",
				"x-foo",
				"x-bar,x-foo",
			},
			notSubs: []string{
				"x-qux",
				"x-qux,x-bar",
				"x-qux,x-foo",
				"x-qux,x-baz,x-foo",
			},
			size:  2,
			slice: []string{"X-Bar", "X-Foo"},
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
