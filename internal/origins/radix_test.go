package origins_test

import (
	"slices"
	"testing"

	"github.com/jub0bs/cors/internal/origins"
)

func TestTree(t *testing.T) {
	cases := []struct {
		desc     string
		patterns []string
		accepts  []string
		rejects  []string
		elems    []string
	}{
		{
			desc: "empty tree",
			rejects: []string{
				"https://cat",
				"https://concat",
				"https://kin",
				"https://pin",
			},
		}, {
			desc: "wildcard-free patterns",
			patterns: []string{
				"https://cat",
				"https://concat",
				"https://kin",
				"https://pin",
			},
			elems: []string{
				"https://cat",
				"https://concat",
				"https://kin",
				"https://pin",
			},
			accepts: []string{
				"https://cat",
				"https://concat",
				"https://kin",
				"https://pin",
			},
			rejects: []string{
				// different scheme
				"http://cat",
				"http://concat",
				"http://kin",
				"http://pin",
				// different port
				"https://cat:1",
				"https://concat:1",
				"https://kin:1",
				"https://pin:1",
				// truncated host (at the end)
				"https://ca",
				"https://con",
				"https://ki",
				"https://p",
				// truncated host (at the start)
				"https://at",
				"https://ncat",
				"https://in",
				"https://n",
				// host prepended with rubbish
				"https://copycat",
				"https://stringconcat",
				"https://akin",
				"https://bespin",
				// regression tests for GHSA-vhxv-fg4m-p2w8
				"https://pkin",
				"https://kpin",
			},
		}, {
			desc: "duplicate patterns",
			patterns: []string{
				"https://cat",
				"https://concat",
				"https://kin",
				"https://pin",
				"https://cat",
				"https://concat",
				"https://kin",
				"https://pin",
			},
			elems: []string{
				"https://cat",
				"https://concat",
				"https://kin",
				"https://pin",
			},
			accepts: []string{
				"https://cat",
				"https://concat",
				"https://kin",
				"https://pin",
			},
			rejects: []string{
				// different scheme
				"http://cat",
				"http://concat",
				"http://kin",
				"http://pin",
				// different port
				"https://cat:1",
				"https://concat:1",
				"https://kin:1",
				"https://pin:1",
				// truncated host (at the end)
				"https://ca",
				"https://con",
				"https://ki",
				"https://p",
				// truncated host (at the start)
				"https://at",
				"https://ncat",
				"https://in",
				"https://n",
				// host prepended with rubbish
				"https://copycat",
				"https://stringconcat",
				"https://akin",
				"https://bespin",
				// regression tests for GHSA-vhxv-fg4m-p2w8
				"https://pkin",
				"https://kpin",
			},
		}, {
			desc: "wildcard-free host patterns, multiple ports",
			patterns: []string{
				"https://cat",
				"https://concat",
				"https://kin",
				"https://pin",
				"https://cat:1",
				"https://concat:1",
				"https://kin:1",
				"https://pin:1",
			},
			elems: []string{
				"https://cat",
				"https://cat:1",
				"https://concat",
				"https://concat:1",
				"https://kin",
				"https://kin:1",
				"https://pin",
				"https://pin:1",
			},
			accepts: []string{
				"https://cat",
				"https://concat",
				"https://kin",
				"https://pin",
				"https://cat:1",
				"https://concat:1",
				"https://kin:1",
				"https://pin:1",
			},
			rejects: []string{
				// different scheme
				"http://cat",
				"http://concat",
				"http://kin",
				"http://pin",
				"http://cat:1",
				"http://concat:1",
				"http://kin:1",
				"http://pin:1",
				// different port
				"https://cat:2",
				"https://concat:2",
				"https://kin:2",
				"https://pin:2",
				// truncated host (at the end)
				"https://ca",
				"https://con",
				"https://ki",
				"https://p",
				"https://ca:1",
				"https://con:1",
				"https://ki:1",
				"https://p:1",
				// truncated host (at the start)
				"https://at",
				"https://ncat",
				"https://in",
				"https://n",
				"https://at:1",
				"https://ncat:1",
				"https://in:1",
				"https://n:1",
				// host prepended with rubbish
				"https://copycat",
				"https://stringconcat",
				"https://akin",
				"https://bespin",
				"https://copycat:1",
				"https://stringconcat:1",
				"https://akin:1",
				"https://bespin:1",
				// regression tests for GHSA-vhxv-fg4m-p2w8
				"https://pkin",
				"https://kpin",
				"https://pkin:1",
				"https://kpin:1",
			},
		}, {
			desc: "wildcard-free patterns in reverse insertion order",
			patterns: []string{
				"https://pin",
				"https://kin",
				"https://concat",
				"https://cat",
			},
			elems: []string{
				"https://cat",
				"https://concat",
				"https://kin",
				"https://pin",
			},
			accepts: []string{
				"https://cat",
				"https://concat",
				"https://kin",
				"https://pin",
			},
			rejects: []string{
				// different scheme
				"http://cat",
				"http://concat",
				"http://kin",
				"http://pin",
				// different port
				"https://cat:1",
				"https://concat:1",
				"https://kin:1",
				"https://pin:1",
				// truncated host (at the end)
				"https://ca",
				"https://con",
				"https://ki",
				"https://p",
				// truncated host (at the start)
				"https://at",
				"https://ncat",
				"https://in",
				"https://n",
				// host prepended with rubbish
				"https://copycat",
				"https://stringconcat",
				"https://akin",
				"https://bespin",
				// regression tests for GHSA-vhxv-fg4m-p2w8
				"https://pkin",
				"https://kpin",
			},
		}, {
			desc: "some wildcard-full patterns",
			patterns: []string{
				"https://cat",
				"https://concat",
				"https://*.kin",
				"https://a.kin",
				"https://*.kin:1",
				"https://pin",
			},
			elems: []string{
				"https://*.kin",
				"https://*.kin:1",
				"https://cat",
				"https://concat",
				"https://pin",
			},
			accepts: []string{
				"https://cat",
				"https://concat",
				"https://a.kin",
				"https://pin",
				// extended host, same port
				"https://nap.kin",
				"https://nap.kin:1",
			},
			rejects: []string{
				// different scheme
				"http://cat",
				"http://concat",
				"http://a.kin",
				"http://pin",
				"http://nap.kin",
				"http://nap.kin:1",
				// different port
				"http://cat:1",
				"http://concat:1",
				"http://pin:1",
				// truncated host (at the end)
				"http://ca",
				"http://conca",
				"http://nap.ki",
				"http://p",
				// truncated host (at the start)
				"http://at",
				"http://ncat",
				"http://in",
				"http://n",
				// host prepended with rubbish
				"https://copycat",
				"https://stringconcat",
				"https://bespin",
				// host prepended with rubbish, different port
				"https://nap.kin:2",
				"https://nap.kin:3",
			},
		}, {
			desc: "wildcard-free patterns and wildcard port",
			patterns: []string{
				"https://cat:*",
				"https://cat",
				"https://concat:*",
				"https://kin",
				"https://pin",
			},
			elems: []string{
				"https://cat:*",
				"https://concat:*",
				"https://kin",
				"https://pin",
			},
			accepts: []string{
				"https://cat",
				"https://concat",
				"https://cat:1",
				"https://concat:1",
				"https://kin",
				"https://pin",
			},
			rejects: []string{
				// different scheme
				"http://cat",
				"http://concat",
				"http://cat:1",
				"http://concat:1",
				"http://kin",
				"http://pin",
				// different value
				"http://kin:1",
				"http://pin:1",
				// truncated host (at the end)
				"https://ca",
				"https://con",
				"https://ki",
				"https://p",
				// truncated host (at the start)
				"https://at",
				"https://ncat",
				"https://in",
				"https://n",
				// host prepended with rubbish
				"https://copycat",
				"https://stringconcat",
				"https://akin",
				"https://bespin",
				// regression tests for GHSA-vhxv-fg4m-p2w8
				"https://pkin",
				"https://kpin",
			},
		}, {
			desc: "some wildcard-full patterns and wildcard port",
			patterns: []string{
				"https://cat",
				"https://concat",
				"https://*.kin:*",
				"https://*.kin",
				"https://pin",
			},
			elems: []string{
				"https://*.kin:*",
				"https://cat",
				"https://concat",
				"https://pin",
			},
			accepts: []string{
				"https://cat",
				"https://concat",
				"https://pin",
				// extended host, arbitrary port
				"https://nap.kin",
				"https://nap.kin:1",
				"https://nap.kin:65355",
			},
			rejects: []string{
				// different scheme
				"http://cat",
				"http://concat",
				"http://pin",
				"http://nap.kin",
				"http://nap.kin:1",
				"http://nap.kin:65355",
				// different port
				"https://cat:1",
				"https://concat:1",
				"https://pin:1",
				// truncated host (at the end)
				"https://ca",
				"https://con",
				"https://nap.ki",
				"https://p",
				// truncated host (at the start)
				"https://at",
				"https://ncat",
				"https://in",
				"https://n",
				// host prepended with rubbish
				"https://copycat",
				"https://stringconcat",
				"https://bespin",
			},
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			tree := new(origins.Tree)
			for _, raw := range tc.patterns {
				pattern, err := origins.ParsePattern(raw)
				if err != nil {
					t.Fatalf("origins.ParsePattern(%q): got non-nil error; want nil", raw)
				}
				tree.Insert(&pattern)
			}
			for _, raw := range tc.accepts {
				origin, ok := origins.Parse(raw)
				if !ok {
					t.Fatalf("origins.Parse(%q): got false; want true", raw)
				}
				if !tree.Contains(&origin) {
					t.Errorf("tree.Contains(%q): got false; want true", raw)
				}
			}
			for _, raw := range tc.rejects {
				origin, ok := origins.Parse(raw)
				if !ok {
					t.Fatalf("origins.Parse(%q): got false; want true", raw)
				}
				if tree.Contains(&origin) {
					t.Errorf("tree.Contains(%q): got true; want false", raw)
				}
			}
			elems := tree.Elems()
			if !slices.Equal(elems, tc.elems) {
				t.Errorf("tree.Elems(): got %q; want %q", elems, tc.elems)
			}
		}
		t.Run(tc.desc, f)
	}
}
