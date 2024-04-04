package util

import (
	"strings"
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
