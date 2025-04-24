package headers

// TrimOWS trims up to n bytes of [optional whitespace (OWS)]
// from the start of and/or the end of s.
// If no more than n bytes of OWS are found at the start of s
// and no more than n bytes of OWS are found at the end of s,
// it returns the trimmed result and true.
// Otherwise, it returns some unspecified string and false.
//
// [optional whitespace (OWS)]: https://httpwg.org/specs/rfc9110.html#whitespace
func TrimOWS(s string, n int) (_ string, _ bool) {
	for i := range len(s) {
		if !isOWS(s[i]) {
			s = s[i:]
			break
		}
		if i >= n {
			return
		}
	}
	for i := len(s); i > 0; i-- {
		if !isOWS(s[i-1]) {
			return s[:i], true
		}
		if i <= len(s)-n {
			return
		}
	}
	return "", true
}

// see https://httpwg.org/specs/rfc9110.html#whitespace
func isOWS(b byte) bool {
	return b == '\t' || b == ' '
}
