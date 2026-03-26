package headers

import (
	"net/http"

	"golang.org/x/net/http/httpguts"
)

const ( // header names in canonical format
	// common request headers
	Origin = "Origin"

	// preflight-only request headers
	ACRM = "Access-Control-Request-Method"
	ACRH = "Access-Control-Request-Headers"

	// common response headers
	ACAO = "Access-Control-Allow-Origin"
	ACAC = "Access-Control-Allow-Credentials"

	// preflight-only response headers
	ACAM = "Access-Control-Allow-Methods"
	ACAH = "Access-Control-Allow-Headers"
	ACMA = "Access-Control-Max-Age"

	// actual-only response headers
	ACEH = "Access-Control-Expose-Headers"

	Vary = "Vary"
)

const Authorization = "authorization" // note: byte-lowercase

const (
	ValueTrue         = "true"
	ValueWildcard     = "*"
	ValueSep          = ","
	ValueWildcardAuth = ValueWildcard + ValueSep + Authorization
)

// IsValid reports whether name is a valid header name,
// [per the Fetch standard].
//
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#header-name
func IsValid(name string) bool {
	return httpguts.ValidHeaderFieldName(name)
}

// First, if k is present in hdrs and len(hdrs[k]) > 0, returns
// (*[1]string)(hdrs[k]) and true; otherwise, it returns nil and false.
//
// First is a useful alternative to [http.Header.Get] because it returns a
// *[1]string result
//   - which can be converted to a slice without incurring any heap allocation,
//   - whose single element (if the result is not nil) can be accessed without
//     incurring any bounds check.
//
// Precondition: k is in canonical format (see [http.CanonicalHeaderKey]).
func First(hdrs http.Header, k string) (*[1]string, bool) {
	v, found := hdrs[k]
	if !found || len(v) < 1 {
		return nil, false
	}
	return (*[1]string)(v), true
}
