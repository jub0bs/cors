package headers

import "github.com/jub0bs/cors/internal/util"

// IsForbiddenResponseHeaderName reports whether name is a
// forbidden response-header name [per the Fetch standard].
//
// Precondition: name is a valid and [byte-lowercase] header name.
//
// [byte-lowercase]: https://infra.spec.whatwg.org/#byte-lowercase
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#forbidden-response-header-name
func IsForbiddenResponseHeaderName(name string) bool {
	return forbiddenResponseHeaderNames.Contains(name)
}

var forbiddenResponseHeaderNames = util.NewSet(
	"set-cookie",
	"set-cookie2",
)

// IsProhibitedResponseHeaderName reports whether name is a prohibited
// response-header name. Attempts to expose such response headers almost
// always stem from some misunderstanding of CORS.
//
// Precondition: name is a valid and [byte-lowercase] header name.
//
// [byte-lowercase]: https://infra.spec.whatwg.org/#byte-lowercase
func IsProhibitedResponseHeaderName(name string) bool {
	return prohibitedResponseHeaderNames.Contains(name)
}

var prohibitedResponseHeaderNames = util.NewSet(
	util.ByteLowercase(Origin),
	util.ByteLowercase(ACRM),
	util.ByteLowercase(ACRH),
	util.ByteLowercase(ACRPN),
	util.ByteLowercase(ACAM),
	util.ByteLowercase(ACAH),
	util.ByteLowercase(ACMA),
	util.ByteLowercase(ACAPN),
)

// IsSafelistedResponseHeaderName reports whether name is a
// safelisted response-header name [per the Fetch standard].
//
// Precondition: name is a valid and [byte-lowercase] header name.
//
// [byte-lowercase]: https://infra.spec.whatwg.org/#byte-lowercase
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#cors-safelisted-response-header-name
func IsSafelistedResponseHeaderName(name string) bool {
	return safelistedResponseHeaderNames.Contains(name)
}

var safelistedResponseHeaderNames = util.NewSet(
	"cache-control",
	"content-language",
	"content-length",
	"content-type",
	"expires",
	"last-modified",
	"pragma",
)
