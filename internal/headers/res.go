package headers

// IsForbiddenResponseHeaderName reports whether name is a
// forbidden response-header name [per the Fetch standard].
//
// Precondition: name is a valid and [byte-lowercase] header name.
//
// [byte-lowercase]: https://infra.spec.whatwg.org/#byte-lowercase
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#forbidden-response-header-name
func IsForbiddenResponseHeaderName(name string) bool {
	switch name {
	case "set-cookie",
		"set-cookie2":
		return true
	default:
		return false
	}
}

// IsProhibitedResponseHeaderName reports whether name is a prohibited
// response-header name. Attempts to expose such response headers almost
// always stem from some misunderstanding of CORS.
//
// Precondition: name is a valid and [byte-lowercase] header name.
//
// [byte-lowercase]: https://infra.spec.whatwg.org/#byte-lowercase
func IsProhibitedResponseHeaderName(name string) bool {
	switch name {
	case "origin",
		"access-control-request-method",
		"access-control-request-headers",
		"access-control-request-private-network",
		"access-control-allow-methods",
		"access-control-allow-headers",
		"access-control-max-age",
		"access-control-allow-private-network":
		return true
	default:
		return false
	}
}

// IsSafelistedResponseHeaderName reports whether name is a
// safelisted response-header name [per the Fetch standard].
//
// Precondition: name is a valid and [byte-lowercase] header name.
//
// [byte-lowercase]: https://infra.spec.whatwg.org/#byte-lowercase
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#cors-safelisted-response-header-name
func IsSafelistedResponseHeaderName(name string) bool {
	switch name {
	case "cache-control",
		"content-language",
		"content-length",
		"content-type",
		"expires",
		"last-modified",
		"pragma":
		return true
	default:
		return false
	}
}
