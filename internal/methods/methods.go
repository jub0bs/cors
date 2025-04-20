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
	switch uppercase := util.ByteUppercase(name); uppercase {
	case http.MethodConnect,
		http.MethodTrace,
		"TRACK":
		return true
	default:
		return false
	}
}

// IsSafelisted reports whether name is a safelisted method,
// [per the Fetch standard].
//
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#cors-safelisted-method
func IsSafelisted(name string) bool {
	switch name {
	case http.MethodGet,
		http.MethodHead,
		http.MethodPost:
		return true
	default:
		return false
	}
}

// Normalize normalizes method, [per the Fetch standard].
//
// [per the Fetch standard]: https://fetch.spec.whatwg.org/#concept-method-normalize
func Normalize(method string) string {
	switch uppercase := util.ByteUppercase(method); uppercase {
	case http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPost,
		http.MethodPut:
		return uppercase
	default:
		return method
	}
}
