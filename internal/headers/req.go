package headers

import (
	"strings"

	"github.com/jub0bs/cors/internal/util"
)

// IsForbiddenRequestHeaderName reports whether name is a
// forbidden request-header name [per the Fetch standard].
//
// Precondition: name is a valid and [byte-lowercase] header name.
//
// [byte-lowercase]: https://infra.spec.whatwg.org/#byte-lowercase
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#forbidden-header-name
func IsForbiddenRequestHeaderName(name string) bool {
	if discreteForbiddenRequestHeaderNames.Contains(name) {
		return true
	}
	return strings.HasPrefix(name, "proxy-") ||
		strings.HasPrefix(name, "sec-")
}

var discreteForbiddenRequestHeaderNames = util.NewSet(
	"accept-charset",
	"accept-encoding",
	util.ByteLowercase(ACRH),
	util.ByteLowercase(ACRM),
	// see https://wicg.github.io/private-network-access/#forbidden-header-names
	util.ByteLowercase(ACRPN),
	"connection",
	"content-length",
	"cookie",
	"cookie2",
	"date",
	"dnt",
	"expect",
	"host",
	"keep-alive",
	util.ByteLowercase(Origin),
	"referer",
	"set-cookie",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"via",
)

// IsProhibitedRequestHeaderName reports whether name is a prohibited
// request-header name. Attempts to allow such request headers almost
// always stem from some misunderstanding of CORS.
//
// Precondition: name is a valid and [byte-lowercase] header name.
//
// [byte-lowercase]: https://infra.spec.whatwg.org/#byte-lowercase
func IsProhibitedRequestHeaderName(name string) bool {
	return prohibitedRequestHeaderNames.Contains(name)
}

var prohibitedRequestHeaderNames = util.NewSet(
	util.ByteLowercase(ACAO),
	util.ByteLowercase(ACAC),
	util.ByteLowercase(ACAM),
	util.ByteLowercase(ACAH),
	util.ByteLowercase(ACAPN),
	util.ByteLowercase(ACMA),
	util.ByteLowercase(ACEH),
)
