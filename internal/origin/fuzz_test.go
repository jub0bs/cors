package origin

import (
	"strings"
	"testing"
)

func FuzzConsistencyBetweenParsePatternAndParse(f *testing.F) {
	for _, c := range parsePatternCases {
		f.Add(c.input)
	}
	for _, c := range parseCases {
		f.Add(c.input)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		pattern, err := ParsePattern(raw)
		if err != nil ||
			pattern.Kind == PatternKindSubdomains ||
			strings.HasSuffix(raw, ":*") {
			t.Skip()
		}
		if _, ok := Parse(raw); !ok {
			const tmpl = "pattern without wildcard %q fails to parse as an origin"
			t.Errorf(tmpl, raw)
		}
	})
}

func FuzzParsePattern(f *testing.F) {
	for _, c := range parsePatternCases {
		f.Add(c.input)
	}
	for _, c := range parseCases {
		f.Add(c.input)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		pattern, err := ParsePattern(raw)
		if err != nil {
			t.Skip()
		}
		if strings.HasSuffix(raw, ":*") {
			if pattern.Port != anyPort {
				const tmpl = "pattern %q should but does not result" +
					" in a Pattern that allows arbitrary ports"
				t.Errorf(tmpl, raw)
			}
			return
		}
		if strings.Contains(raw, "*") != (pattern.Kind == PatternKindSubdomains) {
			const tmpl = "pattern %q should but does not result" +
				" in a Pattern that allows arbitrary subdomains"
			t.Errorf(tmpl, raw)
		}
	})
}

func FuzzCorpus(f *testing.F) {
	for _, c := range parsePatternCases {
		f.Add(c.input, c.input)
	}
	for _, c := range parseCases {
		f.Add(c.input, c.input)
	}
	f.Fuzz(func(t *testing.T, raw, orig string) {
		pattern, err := ParsePattern(raw)
		if err != nil {
			t.Skip()
		}
		corpus := make(Corpus)
		corpus.Add(pattern)
		o, ok := Parse(orig)
		if !ok || !corpus.Contains(&o) {
			t.Skip()
		}
		const tmpl = "corpus built with pattern %q contains origin %q"
		if pattern.Kind == PatternKindSubdomains {
			if !strings.HasPrefix(longestCommonSuffix(raw, orig), ".") {
				t.Errorf(tmpl, raw, orig)
			}
			return
		}
		if pattern.Port == anyPort {
			if !strings.HasSuffix(longestCommonPrefix(raw, orig), ":") {
				t.Errorf(tmpl, raw, orig)
			}
			return
		}
		if orig != raw {
			t.Errorf(tmpl, raw, orig)
		}
	})
}

func longestCommonPrefix(a, b string) (out string) {
	for i, j := 0, 0; i < len(a) && j < len(b); i, j = i+1, j+1 {
		if a[i] != b[j] {
			out = a[:i+1]
			break
		}
	}
	return
}

func longestCommonSuffix(a, b string) (out string) {
	for i, j := len(a)-1, len(b)-1; 0 <= i && 0 <= j; i, j = i-1, j-1 {
		if a[i] != b[j] {
			out = a[i+1:]
			break
		}
	}
	return
}
