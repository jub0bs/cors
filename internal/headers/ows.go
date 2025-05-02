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
		if i > n {
			return
		}
		if !isOWS(s[i]) {
			s = s[i:]
			for i = len(s); i > 0; i-- {
				if i < len(s)-n {
					return
				}
				if !isOWS(s[i-1]) {
					s = s[:i]
					break
				}
			}
			return s, true
		}
	}
	return "", true
}

// see https://httpwg.org/specs/rfc9110.html#whitespace
func isOWS(b byte) bool {
	return b == '\t' || b == ' '
}
