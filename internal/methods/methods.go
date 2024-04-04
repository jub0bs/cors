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
	return byteLowercasedForbiddenMethods.Contains(util.ByteLowercase(name))
}

var byteLowercasedForbiddenMethods = util.NewSet(
	"connect",
	"trace",
	"track",
)

// IsSafelisted reports whether name is a safelisted method,
// [per the Fetch standard].
//
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#cors-safelisted-method
func IsSafelisted(name string, _ struct{}) bool {
	return safelistedMethods.Contains(name)
}

var safelistedMethods = util.NewSet(
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
)
