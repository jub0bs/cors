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
	if 'A' <= asciiRune && asciiRune <= 'Z' {
		return asciiRune + toLower
	}
	return asciiRune
}

// ByteUppercase returns a [byte-uppercase] version of str.
//
// [byte-uppercase]: https://infra.spec.whatwg.org/#byte-uppercase
func ByteUppercase(str string) string {
	return strings.Map(byteUppercaseOne, str)
}

func byteUppercaseOne(asciiRune rune) rune {
	if 'a' <= asciiRune && asciiRune <= 'z' {
		return asciiRune - toLower
	}
	return asciiRune
}

const toLower = 'a' - 'A'
