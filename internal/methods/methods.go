package methods

import (
	"net/http"

	"github.com/jub0bs/cors/internal/util"
	"golang.org/x/net/http/httpguts"
)

// IsValid reports whether name is a valid method, [per the Fetch standard].
//
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#concept-method
func IsValid(name string) bool {
	// Note: the production is identical to that of header names.
	return httpguts.ValidHeaderFieldName(name)
}

// IsForbidden reports whether name is a forbidden method,
// [per the Fetch standard].
//
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#forbidden-method
func IsForbidden(name string) bool {
	return byteUppercasedForbiddenMethods.Contains(util.ByteUppercase(name))
}

// Note: because users are more likely to submit methods in uppercase,
// we store them in the same case with the hope to save a few allocations.
var byteUppercasedForbiddenMethods = util.NewSet(
	"CONNECT",
	"TRACE",
	"TRACK",
)

// IsSafelisted reports whether name is a safelisted method,
// [per the Fetch standard].
//
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#cors-safelisted-method
func IsSafelisted(name string) bool {
	return safelistedMethods.Contains(name)
}

var safelistedMethods = util.NewSet(
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
)

// Normalize normalizes method, [per the Fetch standard].
//
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#concept-method-normalize
func Normalize(method string) string {
	uppercase := util.ByteUppercase(method)
	if browserNormalizedMethods.Contains(uppercase) {
		return uppercase
	}
	return method
}

var browserNormalizedMethods = util.NewSet(
	http.MethodDelete,
	http.MethodGet,
	http.MethodHead,
	http.MethodOptions,
	http.MethodPost,
	http.MethodPut,
)
