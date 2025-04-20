package headers

import "strings"

// IsForbiddenRequestHeaderName reports whether name is a
// forbidden request-header name [per the Fetch standard].
//
// Precondition: name is a valid and [byte-lowercase] header name.
//
// [byte-lowercase]: https://infra.spec.whatwg.org/#byte-lowercase
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#forbidden-header-name
func IsForbiddenRequestHeaderName(name string) bool {
	switch name {
	case "accept-charset",
		"accept-encoding",
		"access-control-request-headers",
		"access-control-request-method",
		// see https://wicg.github.io/private-network-access/#forbidden-header-names
		"access-control-request-private-network",
		"connection",
		"content-length",
		"cookie",
		"cookie2",
		"date",
		"dnt",
		"expect",
		"host",
		"keep-alive",
		"origin",
		"referer",
		"set-cookie",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
		"via":
		return true
	default:
		return strings.HasPrefix(name, "proxy-") ||
			strings.HasPrefix(name, "sec-")
	}
}

// IsProhibitedRequestHeaderName reports whether name is a prohibited
// request-header name. Attempts to allow such request headers almost
// always stem from some misunderstanding of CORS.
//
// Precondition: name is a valid and [byte-lowercase] header name.
//
// [byte-lowercase]: https://infra.spec.whatwg.org/#byte-lowercase
func IsProhibitedRequestHeaderName(name string) bool {
	switch name {
	case "access-control-allow-origin",
		"access-control-allow-credentials",
		"access-control-allow-methods",
		"access-control-allow-headers",
		"access-control-allow-private-network",
		"access-control-max-age",
		"access-control-expose-headers":
		return true
	default:
		return false
	}
}
