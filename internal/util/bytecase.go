package util

import (
	"strings"
)

// ByteLowercase returns a [byte-lowercase] version of ASCII string str.
//
// [byte-lowercase]: https://infra.spec.whatwg.org/#byte-lowercase
func ByteLowercase(str string) string {
	return strings.ToLower(str)
}

// ByteUppercase returns a [byte-uppercase] version of ASCII string str.
//
// [byte-uppercase]: https://infra.spec.whatwg.org/#byte-uppercase
func ByteUppercase(str string) string {
	return strings.ToUpper(str)
}
