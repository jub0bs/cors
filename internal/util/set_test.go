package util_test

import (
	"slices"
	"testing"

	"github.com/jub0bs/cors/internal/util"
)

func TestSet(t *testing.T) {
	cases := []struct {
		desc  string
		elems []string
		more  []string
		want  []string
	}{
		{
			desc:  "singleton set",
			elems: []string{"foo"},
			want:  []string{"foo"},
		}, {
			desc:  "no dupes",
			elems: []string{"foo", "bar", "baz"},
			more:  []string{"qux", "quux"},
			want:  []string{"bar", "baz", "foo", "quux", "qux"},
		}, {
			desc:  "some dupes",
			elems: []string{"foo", "bar", "baz"},
			more:  []string{"bar", "baz"},
			want:  []string{"bar", "baz", "foo"},
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			t.Parallel()
			set := util.NewSet(tc.elems...)
			for _, s := range tc.more {
				set.Add(s)
			}
			if size := set.Size(); size != len(tc.want) {
				const tmpl = "got a set of size %d; want %d"
				t.Errorf(tmpl, size, len(tc.want))
			}
			all := append(tc.elems, tc.more...)
			for _, s := range all {
				if !set.Contains(s) {
					const tmpl = "%v does not contain %q, but it should"
					t.Errorf(tmpl, set, s)
				}
			}
			slice := set.ToSlice()
			if !slices.Equal(slice, tc.want) {
				t.Errorf("got %q; want %q", slice, tc.want)
			}
		}
		t.Run(tc.desc, f)
	}
}
