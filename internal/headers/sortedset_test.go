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
		wantSize int
	}{
		{
			desc:     "empty set",
			combined: "",
			notSubs: []string{
				"bar",
				"bar,foo",
			},
			wantSize: 0,
		}, {
			desc:     "singleton set",
			elems:    []string{"foo"},
			combined: "foo",
			subs: []string{
				"",
				"foo",
			},
			notSubs: []string{
				"bar",
				"bar,foo",
			},
			wantSize: 1,
		}, {
			desc:     "no dupes",
			elems:    []string{"foo", "bar", "baz"},
			combined: "bar,baz,foo",
			subs: []string{
				"",
				"bar",
				"baz",
				"foo",
				"bar,baz",
				"bar,foo",
				"baz,foo",
				"bar,baz,foo",
			},
			notSubs: []string{
				"qux",
				"bar,baz,baz",
				"qux,baz",
				"qux,foo",
				"quxbaz,foo",
			},
			wantSize: 3,
		}, {
			desc:     "some dupes",
			elems:    []string{"foo", "bar", "foo"},
			combined: "bar,foo",
			subs: []string{
				"",
				"bar",
				"foo",
				"bar,foo",
			},
			notSubs: []string{
				"qux",
				"qux,bar",
				"qux,foo",
				"qux,baz,foo",
			},
			wantSize: 2,
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			elems := slices.Clone(tc.elems)
			s := headers.NewSortedSet(tc.elems...)
			size := s.Size()
			if s.Size() != tc.wantSize {
				const tmpl = "NewSortedSet(%#v...).Size(): got %d; want %d"
				t.Errorf(tmpl, elems, size, tc.wantSize)
			}
			combined := s.String()
			if combined != tc.combined {
				const tmpl = "NewSortedSet(%#v...).String(): got %q; want %q"
				t.Errorf(tmpl, elems, combined, tc.combined)
			}
			for _, sub := range tc.subs {
				if !s.Subsumes(sub) {
					const tmpl = "%q does not subsume %q, but should"
					t.Errorf(tmpl, s, sub)
				}
			}
			for _, notSub := range tc.notSubs {
				if s.Subsumes(notSub) {
					const tmpl = "%q subsumes %q, but should not"
					t.Errorf(tmpl, s, notSub)
				}
			}
		}
		t.Run(tc.desc, f)
	}
}
