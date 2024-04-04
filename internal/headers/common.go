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
	ACRPN = "Access-Control-Request-Private-Network"
	ACRM  = "Access-Control-Request-Method"
	ACRH  = "Access-Control-Request-Headers"

	// common response headers
	ACAO = "Access-Control-Allow-Origin"
	ACAC = "Access-Control-Allow-Credentials"

	// preflight-only response headers
	ACAPN = "Access-Control-Allow-Private-Network"
	ACAM  = "Access-Control-Allow-Methods"
	ACAH  = "Access-Control-Allow-Headers"
	ACMA  = "Access-Control-Max-Age"

	// actual-only response headers
	ACEH = "Access-Control-Expose-Headers"

	Vary = "Vary"
)

const Authorization = "authorization" // note: byte-lowercase

const (
	ValueTrue        = "true"
	ValueWildcard    = "*"
	ValueVaryOptions = ACRH + ", " + ACRM + ", " + ACRPN + ", " + Origin
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

// First, if k is present in hdrs, returns the value associated to k in hdrs,
// a singleton slice containing that value, and true;
// otherwise, First returns "", nil, false.
// Precondition: k is in canonical format (see [http.CanonicalHeaderKey]).
//
// First is useful because
//   - contrary to [http.Header.Get], it returns a slice that can be reused,
//     which saves a heap allocation in client code;
//   - it returns the value both as a scalar and as a singleton slice,
//     which saves a bounds check in client code.
func First(hdrs http.Header, k string) (string, []string, bool) {
	v, found := hdrs[k]
	if !found || len(v) == 0 {
		return "", nil, false
	}
	return v[0], v[:1], true
}
