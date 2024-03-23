package headers

import (
	"net/http"

	"github.com/jub0bs/cors/internal/util"
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
	ValueTrue     = "true"
	ValueWildcard = "*"
)

const ValueSep = ","

var ( // each of them an effective constant wrapped in a (singleton) slice
	PreflightVarySgl = []string{ACRH + ", " + ACRM + ", " + ACRPN + ", " + Origin}
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
	return util.IsToken(name)
}

// FastAdd adds the key-value pair (k, v[0]) in hdrs.
// FastAdd is useful because, contrary to [http.Header.Add],
// it incurs no heap allocation when k is absent from hdrs.
// Preconditions:
//   - hdrs is non-nil;
//   - k is in canonical format (see [http.CanonicalHeaderKey]);
//   - v is a singleton slice.
func FastAdd(hdrs http.Header, k string, v []string) {
	old, found := hdrs[k]
	if !found { // fast path
		hdrs[k] = v
		return
	}
	// slow path
	hdrs[k] = append(old, v[0])
}

// First, if k is present in hdrs, returns a singleton slice containing
// the first value (if any) associated with k in hdrs and true.
// Otherwise, First returns nil and false.
// First is useful because, contrary to [http.Header.Get],
// it returns a slice that can be reused, which avoids a heap allocation.
// Precondition: k is in canonical format (see [http.CanonicalHeaderKey]).
func First(hdrs http.Header, k string) ([]string, bool) {
	v, found := hdrs[k]
	if !found || len(v) == 0 {
		return nil, false
	}
	return v[:1], true
}
