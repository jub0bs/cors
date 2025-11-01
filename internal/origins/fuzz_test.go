package origins

import (
	"net"
	"strconv"
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

func FuzzConsistencyBetweenParseAndSplitHostPort(f *testing.F) {
	for _, c := range parseCases {
		f.Add(c.input)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		origin, ok := Parse(raw)
		if !ok {
			t.Skip()
		}
		// Elide scheme and scheme-host separator.
		_, hostPort, found := strings.Cut(raw, "://")
		if !found {
			t.Skip()
		}
		// Check whether the host is valid;
		// Parse is lenient about this but,
		// if both Parse and parseHostPattern succeed,
		// then we expect the host to be valid.
		_, _, err := parseHostPattern(hostPort, hostPort)
		if err != nil {
			t.Skip()
		}
		// Check the port; if it's absent, skip this case,
		// since net.SplitHostPort would choke on it.
		if origin.Port == 0 {
			t.Skip()
		}
		wantHost, wantPort, err := net.SplitHostPort(hostPort)
		if err != nil {
			t.Fatal(err)
		}
		gotHost := origin.Host
		gotPort := strconv.FormatInt(int64(origin.Port), 10)
		if gotHost != wantHost || gotPort != wantPort {
			const tmpl = "(host, port) of %q: got (%q, %s); want (%q, %s)"
			t.Errorf(tmpl, hostPort, gotHost, gotPort, wantHost, wantPort)
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
		if pattern.HostPattern.Value == "" {
			const tmpl = "pattern %q should but does not result" +
				" in a Pattern that whose host is empty"
			t.Errorf(tmpl, raw)
		}
		if strings.HasSuffix(raw, ":*") {
			if pattern.Port != wildcardPort {
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

func FuzzTree(f *testing.F) {
	for _, c := range parsePatternCases {
		f.Add(c.input, c.input)
	}
	for _, c := range parseCases {
		f.Add(c.input, c.input)
	}
	f.Fuzz(func(t *testing.T, rawPattern, rawOrigin string) {
		pattern, err := ParsePattern(rawPattern)
		if err != nil {
			t.Skip()
		}
		tree := new(Tree)
		tree.Insert(&pattern)
		origin, ok := Parse(rawOrigin)
		if !ok || !tree.Contains(&origin) {
			t.Skip()
		}
		const tmpl = "tree built with pattern %q contains origin %q"
		if pattern.Kind == PatternKindSubdomains {
			if !strings.HasPrefix(longestCommonSuffix(rawPattern, rawOrigin), ".") {
				t.Errorf(tmpl, rawPattern, rawOrigin)
			}
			return
		}
		if pattern.Port == wildcardPort {
			if !strings.HasSuffix(longestCommonPrefix(rawPattern, rawOrigin), ":") {
				t.Errorf(tmpl, rawPattern, rawOrigin)
			}
			return
		}
		if rawOrigin != rawPattern {
			t.Errorf(tmpl, rawPattern, rawOrigin)
		}
	})
}

func longestCommonPrefix(a, b string) string {
	var i int
	for m := min(len(a), len(b)); i < m && a[i] == b[i]; i++ {
		// deliberately empty body
	}
	return a[:i]
}

func longestCommonSuffix(a, b string) string {
	m := min(len(a), len(b))
	a = a[len(a)-m:]
	b = b[len(b)-m:]
	_ = b[:len(a)] // hoist bounds check on b out of the loop
	i := len(a) - 1
	for ; 0 <= i && a[i] == b[i]; i-- {
		// deliberately empty body
	}
	return a[i+1:]
}
