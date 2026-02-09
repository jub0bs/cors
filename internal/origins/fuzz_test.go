package origins

import (
	"strings"
	"testing"
)

func Fuzz_consistency_between_ParsePattern_and_Parse(f *testing.F) {
	for _, c := range parsePatternTestCases {
		f.Add(c.input)
	}
	for _, c := range parseTestCases {
		f.Add(c.input)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		pattern, err := ParsePattern(raw)
		if err != nil ||
			pattern.Kind == ArbitrarySubdomains ||
			strings.HasSuffix(raw, ":*") {
			t.Skip()
		}
		if _, ok := Parse(raw); !ok {
			const tmpl = "pattern without wildcard %q fails to parse as an origin"
			t.Errorf(tmpl, raw)
		}
	})
}

func Fuzz_ParsePattern(f *testing.F) {
	for _, c := range parsePatternTestCases {
		f.Add(c.input)
	}
	for _, c := range parseTestCases {
		f.Add(c.input)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		pattern, err := ParsePattern(raw)
		if err != nil {
			t.Skip()
		}
		if pattern.HostPattern == "" {
			const tmpl = "pattern %q should but does not result in a Pattern whose host is empty"
			t.Errorf(tmpl, raw)
		}
		if strings.HasSuffix(raw, ":*") {
			if pattern.Port != arbitraryPort {
				const tmpl = "pattern %q should but does not result in a Pattern that allows arbitrary ports"
				t.Errorf(tmpl, raw)
			}
			return
		}
		if strings.Contains(raw, "*") != (pattern.Kind == ArbitrarySubdomains) {
			const tmpl = "pattern %q should but does not result in a Pattern that allows arbitrary subdomains"
			t.Errorf(tmpl, raw)
		}
	})
}
