package util_test

import (
	"testing"

	"github.com/jub0bs/cors/internal/util"
)

func TestSet(t *testing.T) {
	cases := []struct {
		desc  string
		first string
		rest  []string
		more  []string
		want  string
	}{
		{
			desc:  "singleton set",
			first: "foo",
			want:  "foo",
		}, {
			desc:  "no dupes",
			first: "foo",
			rest:  []string{"bar", "baz"},
			more:  []string{"qux", "quux"},
			want:  "bar,baz,foo,quux,qux",
		}, {
			desc:  "some dupes",
			first: "foo",
			rest:  []string{"bar", "baz"},
			more:  []string{"bar", "baz"},
			want:  "bar,baz,foo",
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			set := util.NewSet(tc.first, tc.rest...)
			for _, s := range tc.more {
				set.Add(s)
			}
			if maxSize := 1 + len(tc.rest) + len(tc.more); len(set) > maxSize {
				const tmpl = "got a set of size %d; want at most  %d"
				t.Errorf(tmpl, len(set), maxSize)
			}
			all := append(tc.rest, tc.more...)
			all = append(all, tc.first)
			for _, s := range all {
				if !set.Contains(s) {
					const tmpl = "%v does not contain %q, but it should"
					t.Errorf(tmpl, set, s)
				}
			}
		}
		t.Run(tc.desc, f)
	}
}
