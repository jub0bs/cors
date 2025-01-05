/*
Package cfgerrors provides functionalities for programmatically handling
configuration errors returned by [github.com/jub0bs/cors.NewMiddleware] and
[github.com/jub0bs/cors.Middleware.Reconfigure].

Most users of [github.com/jub0bs/cors] have no use for this package.
However, multi-tenant SaaS companies that allow their tenants to configure CORS
(e.g. via some Web portal) may find this package useful:
it indeed allows those companies to inform their tenants about
CORS-configuration mistakes via custom, human-friendly error messages,
perhaps even ones written in a natural language other than English
and/or generated on the client side.
*/
package cfgerrors

import (
	"fmt"
	"iter"
)

// An UnacceptableOriginPatternError indicates an unacceptable origin pattern.
// The Reason field may take one of three values:
//   - "missing": no origin pattern was specified;
//   - "invalid": the origin pattern is invalid;
//   - "prohibited": the origin pattern is prohibited by this library.
//
// For more details, see [github.com/jub0bs/cors.Config.Origins].
type UnacceptableOriginPatternError struct {
	Value  string // the unacceptable value that was specified
	Reason string // missing | invalid | prohibited
}

func (err *UnacceptableOriginPatternError) Error() string {
	if err.Reason == "missing" {
		return "cors: at least one origin must be allowed"
	}
	const tmpl = "cors: %s origin pattern %q"
	return fmt.Sprintf(tmpl, err.Reason, err.Value)
}

// An UnacceptableMethodError indicates an unacceptable method.
// The Reason field may take one of two values:
//   - "invalid": the method is invalid;
//   - "forbidden": the method is forbidden by [the Fetch standard].
//
// For more details, see [github.com/jub0bs/cors.Config.Methods].
//
// [the Fetch standard]: https://fetch.spec.whatwg.org
type UnacceptableMethodError struct {
	Value  string // the unacceptable value that was specified
	Reason string // invalid | forbidden
}

func (err *UnacceptableMethodError) Error() string {
	const tmpl = "cors: %s method %q"
	return fmt.Sprintf(tmpl, err.Reason, err.Value)
}

// An UnacceptableHeaderNameError indicates an unacceptable header name.
// The Type field may take one of two values:
//   - "request";
//   - "response".
//
// The Reason field may take one of three values:
//   - "invalid": the header name is invalid;
//   - "prohibited": the header name is prohibited by this library;
//   - "forbidden": the header name is forbidden by [the Fetch standard].
//
// For more details, see [github.com/jub0bs/cors.Config.RequestHeaders] and
// [github.com/jub0bs/cors.Config.ResponseHeaders].
//
// [the Fetch standard]: https://fetch.spec.whatwg.org
type UnacceptableHeaderNameError struct {
	Value  string // the unacceptable value that was specified
	Type   string // request | response
	Reason string // invalid | prohibited | forbidden
}

func (err *UnacceptableHeaderNameError) Error() string {
	const tmpl = "cors: %s %s-header name %q"
	return fmt.Sprintf(tmpl, err.Reason, err.Type, err.Value)
}

// A MaxAgeOutOfBoundsError indicates a max-age value that's either too low
// or too high.
//
// For more details, see [github.com/jub0bs/cors.Config.MaxAgeInSeconds].
type MaxAgeOutOfBoundsError struct {
	Value   int // the unacceptable value that was specified
	Default int // max-age value used by browsers if MaxAgeInSeconds is 0
	Max     int // maximum max-age value allowed by this library
	Disable int // sentinel value for disabling preflight caching
}

func (err *MaxAgeOutOfBoundsError) Error() string {
	const tmpl = "cors: out-of-bounds max-age value %d (default: %d; max: %d; disable caching: %d)"
	return fmt.Sprintf(tmpl, err.Value, err.Default, err.Max, err.Disable)
}

// A PreflightSuccessStatusOutOfBoundsError indicates a preflight-success status
// that's either too low or too high.
//
// For more details, see [github.com/jub0bs/cors.Config.PreflightSuccessStatus].
type PreflightSuccessStatusOutOfBoundsError struct {
	Value   int // the unacceptable value that was specified
	Default int // default value used by this library
	Min     int // minimum value for an ok status
	Max     int // maximum value for an ok status
}

func (err *PreflightSuccessStatusOutOfBoundsError) Error() string {
	const tmpl = "cors: out-of-bounds preflight-success status %d (default: %d; min: %d; max: %d)"
	return fmt.Sprintf(tmpl, err.Value, err.Default, err.Min, err.Max)
}

// An IncompatibleOriginPatternError indicates an origin pattern that conflicts
// with other elements of the configuration. Five cases are possible:
//   - Value == "*" and Reason == "credentialed": the wildcard origin was
//     specified and credentialed access was enabled.
//   - Value == "*" and Reason == "pna": the wildcard origin was
//     specified and Private-Network Access was enabled.
//   - Value != "*" and Reason == "credentialed": an insecure origin pattern
//     was specified and credentialed access was enabled without also setting
//     [github.com/jub0bs/cors.ExtraConfig.DangerouslyTolerateInsecureOriginPatterns].
//   - Value != "*" and Reason == "pna": an insecure origin pattern was
//     specified and one form of Private-Network Access was enabled without also
//     setting
//     [github.com/jub0bs/cors.ExtraConfig.DangerouslyTolerateInsecureOriginPatterns].
//   - Reason == "psl": an origin pattern that encompasses arbitrary subdomains
//     of a public suffix was specified without also setting
//     [github.com/jub0bs/cors.ExtraConfig.DangerouslyTolerateSubdomainsOfPublicSuffixes].
//
// For more details, see [github.com/jub0bs/cors.Config.Origins].
type IncompatibleOriginPatternError struct {
	Value  string // "*" | some other origin pattern
	Reason string // credentialed | pna | psl
}

func (err *IncompatibleOriginPatternError) Error() string {
	switch {
	case err.Value == "*" && err.Reason == "credentialed":
		return "cors: for security reasons, you cannot both allow all origins and enable credentialed access"
	case err.Value == "*" && err.Reason == "pna":
		return "cors: for security reasons, you cannot both allow all origins and enable Private-Network Access"
	case err.Reason == "credentialed":
		const tmpl = "cors: for security reasons, insecure origin patterns like %q are by default prohibited when credentialed access is enabled"
		return fmt.Sprintf(tmpl, err.Value)
	case err.Reason == "pna":
		const tmpl = "cors: for security reasons, insecure origin patterns like %q are by default prohibited when Private-Network Access is enabled"
		return fmt.Sprintf(tmpl, err.Value)
	case err.Reason == "psl":
		const tmpl = "cors: for security reasons, origin patterns like %q that encompass subdomains of a public suffix are by default prohibited"
		return fmt.Sprintf(tmpl, err.Value)
	default:
		// We never produce such errors; this case only exists to make the
		// compiler happy.
		return "cors: unknown issue"
	}
}

// An IncompatiblePrivateNetworkAccessModesError indicates an attempt
// to enable both forms of Private-Network Access. For more details,
// see [github.com/jub0bs/cors.ExtraConfig.PrivateNetworkAccess] and
// [github.com/jub0bs/cors.ExtraConfig.PrivateNetworkAccessInNoCORSModeOnly].
type IncompatiblePrivateNetworkAccessModesError struct{}

func (*IncompatiblePrivateNetworkAccessModesError) Error() string {
	return "cors: at most one form of Private-Network Access can be enabled"
}

// An IncompatibleWildcardResponseHeaderNameError indicates an attempt
// to both expose all response headers and enable credentialed access.
// For more details, see [github.com/jub0bs/cors.Config.ResponseHeaders].
type IncompatibleWildcardResponseHeaderNameError struct{}

func (*IncompatibleWildcardResponseHeaderNameError) Error() string {
	return "cors: you cannot both expose all response headers and enable credentialed access"
}

// All returns an iterator over the CORS-configuration errors contained in
// err's error tree. The order is unspecified and may change from one release
// to the next. All only supports error values returned by
// [github.com/jub0bs/cors.NewMiddleware] and
// [github.com/jub0bs/cors.Middleware.Reconfigure]; it should not be called on
// any other error value.
func All(err error) iter.Seq[error] {
	return func(yield func(error) bool) {
		switch err := err.(type) {
		// Note that there's no need for any "interface { Unwrap() error }" case
		// because nowhere do we "wrap" errors; we only ever "join" them.
		case interface{ Unwrap() []error }:
			for _, err := range err.Unwrap() {
				for err := range All(err) {
					if !yield(err) {
						return
					}
				}
			}
		default:
			if !yield(err) {
				return
			}
		}
	}
}
