package headers

import "github.com/jub0bs/cors/internal/util"

var owsSet = util.MakeASCIISet("\t ") // see https://httpwg.org/specs/rfc9110.html#whitespace

// TrimOWS trims up to n bytes of [optional whitespace (OWS)]
// from the start of and/or the end of s.
// If no more than n bytes of OWS are found at the start of s
// and no more than n bytes of OWS are found at the end of s,
// it returns the trimmed result and true.
// Otherwise, it returns the original string and false.
//
// [optional whitespace (OWS)]: https://httpwg.org/specs/rfc9110.html#whitespace
func TrimOWS(s string, n int) (trimmed string, ok bool) {
	if s == "" {
		return s, true
	}
	trimmed, ok = trimRightOWS(s, n)
	if !ok {
		return s, false
	}
	trimmed, ok = trimLeftOWS(trimmed, n)
	if !ok {
		return s, false
	}
	return trimmed, true
}

func trimLeftOWS(s string, n int) (string, bool) {
	sCopy := s
	var i int
	for len(s) > 0 {
		if i > n {
			return sCopy, false
		}
		if !owsSet.Contains(s[0]) {
			// Note: We could simply test s[0] == '\t' || s[0] == ' ',
			// but relying on an asciiSet allows us to
			//  - use one indexing operation instead of two comparisons, and
			//  - not favor one OWS byte (e.g. '\t') over the other (e.g. ' ').
			break
		}
		s = s[1:]
		i++
	}
	return s, true
}

func trimRightOWS(s string, n int) (string, bool) {
	sCopy := s
	var i int
	for len(s) > 0 {
		if i > n {
			return sCopy, false
		}
		if !owsSet.Contains(s[len(s)-1]) {
			// see implementation comment trimLeftOWS
			break
		}
		s = s[:len(s)-1]
		i++
	}
	return s, true
}
