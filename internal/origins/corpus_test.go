package origins_test

import (
	"slices"
	"testing"

	"github.com/jub0bs/cors/internal/origins"
)

func TestCorpus(t *testing.T) {
	cases := []struct {
		desc     string
		patterns []string
		accepts  []string
		rejects  []string
		elems    []string
	}{
		{
			desc:    "empty corpus",
			rejects: []string{"https://example.com"},
		}, {
			desc:     "one discrete origin",
			patterns: []string{"https://example.com"},
			accepts:  []string{"https://example.com"},
			rejects: []string{
				"http://example.com",
				"https://example.com:8080",
				"https://example.org",
				"https://foo.example.com",
			},
			elems: []string{"https://example.com"},
		}, {
			desc: "two discrete origins",
			patterns: []string{
				"https://example.org",
				"https://example.com",
			},
			accepts: []string{
				"https://example.org",
				"https://example.com",
			},
			rejects: []string{
				"http://example.org",
				"https://example.org:8080",
				"https://foo.example.org",
				"http://example.com",
				"https://example.com:8080",
				"https://foo.example.com",
			},
			elems: []string{
				"https://example.com",
				"https://example.org",
			},
		}, {
			desc: "one discrete origin and one wildcard origin pattern",
			patterns: []string{
				"https://*.example.org",
				"https://example.com",
			},
			accepts: []string{
				"https://foo.example.org",
				"https://foo.bar.example.org",
				"https://example.com",
			},
			rejects: []string{
				"https://example.org",
				"http://foo.example.org",
				"http://foo.bar.example.org",
				"https://example.org:8080",
				"http://foo.example.org:8080",
				"http://foo.bar.example.org:8080",
				"http://example.com",
				"https://example.com:8080",
				"https://foo.example.com",
			},
			elems: []string{
				"https://*.example.org",
				"https://example.com",
			},
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			corpus := make(origins.Corpus)
			for _, raw := range tc.patterns {
				pattern, err := origins.ParsePattern(raw)
				if err != nil {
					t.Fatalf("origins.ParsePatten(%q): got non-nil error; want nil", raw)
				}
				corpus.Add(&pattern)
			}
			for _, raw := range tc.accepts {
				origin, ok := origins.Parse(raw)
				if !ok {
					t.Fatalf("origins.Parse(%q): got false; want true", raw)
				}
				if !corpus.Contains(&origin) {
					t.Errorf("corpus.Contains(%q): got false; want true", raw)
				}
			}
			for _, raw := range tc.rejects {
				origin, ok := origins.Parse(raw)
				if !ok {
					t.Fatalf("origins.Parse(%q): got false; want true", raw)
				}
				if corpus.Contains(&origin) {
					t.Errorf("corpus.Contains(%q): got true; want false", raw)
				}
			}
			elems := corpus.Elems()
			if !slices.Equal(elems, tc.elems) {
				t.Errorf("corpus.Elems(): got %q; want %q", elems, tc.elems)
			}
		}
		t.Run(tc.desc, f)
	}
}
