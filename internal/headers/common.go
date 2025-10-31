package headers

import (
	"net/http"

	"golang.org/x/net/http/httpguts"
)

// header names in canonical format
const (
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
	ValueTrue        = "true"
	ValueWildcard    = "*"
	ValueVaryOptions = ACRH + ", " + ACRM + ", " + Origin
)

const ValueSep = ","

var ( // each of them an effective constant wrapped in a (singleton) slice
	PreflightVarySgl = []string{ValueVaryOptions}
	TrueSgl          = []string{ValueTrue}
	OriginSgl        = []string{Origin}
	WildcardSgl      = []string{ValueWildcard}
	WildcardAuthSgl  = []string{ValueWildcard + ValueSep + Authorization}
)

// IsValid reports whether name is a valid header name,
// [per the Fetch standard].
//
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#header-name
func IsValid(name string) bool {
	return httpguts.ValidHeaderFieldName(name)
}

// First, if k is present in hdrs and if the corresponding slice is not empty,
// returns the first element of that slice as a singleton slice and true;
// otherwise, First returns nil and false.
// Precondition: k is in canonical format (see [http.CanonicalHeaderKey]).
//
// First is useful because contrary to [http.Header.Get], it returns a slice,
// which can be reused by the caller to compose a response, thereby obviating
// the need to wrap a string in a slice and saving one heap allocation.
func First(hdrs http.Header, k string) ([]string, bool) {
	if v, found := hdrs[k]; found && len(v) > 0 {
		return v[:1], true
	}
	return nil, false
}
