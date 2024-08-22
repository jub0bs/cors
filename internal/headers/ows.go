package headers

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
		if !owsSet.contains(s[0]) {
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
		if !owsSet.contains(s[len(s)-1]) {
			// see implementation comment trimLeftOWS
			break
		}
		s = s[:len(s)-1]
		i++
	}
	return s, true
}

type asciiSet [8]uint32

var owsSet = makeASCIISet("\t ") // see https://httpwg.org/specs/rfc9110.html#whitespace

// makeASCIISet creates a set of ASCII characters and reports whether all
// characters in chars are ASCII.
// All bytes in chars are assumed to be less < utf8.RuneSelf.
// This implementation is adapted from that of the strings package.
func makeASCIISet(chars string) asciiSet {
	var as asciiSet
	for i := 0; i < len(chars); i++ {
		c := chars[i]
		as[c/32] |= 1 << (c % 32)
	}
	return as
}

// contains reports whether c is inside the set.
func (as *asciiSet) contains(c byte) bool {
	return (as[c/32] & (1 << (c % 32))) != 0
}
