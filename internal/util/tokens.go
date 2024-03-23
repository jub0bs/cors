package util

import (
	"strings"

	"golang.org/x/net/http/httpguts"
)

// ByteLowercase returns a [byte-lowercase] version of str.
//
// [byte-lowercase]: https://infra.spec.whatwg.org/#byte-lowercase
func ByteLowercase(str string) string {
	return strings.Map(byteLowercaseOne, str)
}

func byteLowercaseOne(asciiRune rune) rune {
	const toLower = 'a' - 'A'
	if 'A' <= asciiRune && asciiRune <= 'Z' {
		return asciiRune + toLower
	}
	return asciiRune
}

// IsToken reports whether str is a valid token, per [RFC 9110].
//
// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110#name-tokens
func IsToken(str string) bool {
	if len(str) == 0 {
		return false
	}
	for _, b := range []byte(str) {
		if !httpguts.IsTokenRune(rune(b)) {
			return false
		}
	}
	return true
}
