package cors

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/jub0bs/cors/cfgerrors"
	"github.com/jub0bs/cors/internal/headers"
	"github.com/jub0bs/cors/internal/methods"
	"github.com/jub0bs/cors/internal/origins"
	"github.com/jub0bs/cors/internal/util"
)

// A Config configures a Middleware. The mechanics of and interplay between
// this type's various fields are explained below.
// Attempts to use settings described as "prohibited" result in a failure
// to build the desired middleware.
//
// # Origins
//
// Origins configures a CORS middleware to allow access from any of the
// [Web origins] encompassed by the specified origin patterns:
//
//	Origins: []string{
//	  "https://example.com",
//	  "https://*.example.com",
//	},
//
// Security considerations: Bear in mind that, by allowing Web origins
// in your server's CORS configuration, you engage in a trust relationship
// with those origins.
// Malicious actors may be able to exploit some Web vulnerabilities (including
// [cross-site scripting] and [subdomain takeover]) on those origins and mount
// [cross-origin attacks] against your users from there.
// Therefore, you should (in general) exercise caution when deciding which
// origins to allow. In particular, if you enable [credentialed access],
// you should only allow Web origins that you absolutely trust.
//
// Omitting to specify at least one origin pattern is prohibited;
// so is specifying one or more invalid or prohibited origin pattern(s).
//
// All valid schemes (no longer than 64 bytes) other than file are permitted
// (with one caveat about schemes other than https explained further down):
//
//	http://example.com    // permitted
//	https://example.com   // permitted
//	connector://localhost // permitted
//	file:///somepath      // prohibited
//
// Origins must be specified in [ASCII serialized form]; Unicode is prohibited:
//
//	https://example.com            // permitted
//	https://www.xn--xample-9ua.com // permitted (Punycode)
//	https://www.résumé.com         // prohibited (Unicode)
//
// Because the [null origin] is [fundamentally unsafe], it is prohibited.
//
// Hosts that are IPv4 addresses must be specified in [dotted-quad notation]:
//
//	http://255.0.0.0  // permitted
//	http://0xFF000000 // prohibited
//
// Hosts that are IPv6 addresses must be specified in their [compressed form]:
//
//	http://[::1]:9090                                     // permitted
//	http://[0:0:0:0:0:0:0:0001]:9090                      // prohibited
//	http://[0000:0000:0000:0000:0000:0000:0000:0001]:9090 // prohibited
//
// Valid port values range from 1 to 65,535 (inclusive):
//
//	https://example.com       // permitted (no explicit port)
//	https://example.com:1     // permitted
//	https://example.com:65535 // permitted
//	https://example.com:0     // prohibited
//	https://example.com:65536 // prohibited
//
// Default ports (80 for http, 443 for https) must be elided:
//
//	http://example.com      // permitted
//	https://example.com     // permitted
//	http://example.com:80   // prohibited
//	https://example.com:443 // prohibited
//
// In addition to support for exact origins,
// this field provides limited support for origin patterns
// that encompass multiple origins.
//
// When credentialed access is not enabled
// (i.e. when the Credentialed field is unset),
// a single asterisk denotes all origins:
//
//	Origins: []string{"*"},
//
// For [security reasons], specifying this origin pattern is prohibited
// when credentialed access is enabled:
//
//	Credentialed: true,
//	Origins:      []string{"*"}, // prohibited
//
// A leading asterisk followed by a period (.) in a host pattern
// denotes one or more period-separated arbitrary DNS labels.
// For instance, the pattern
//
//	https://*.example.com
//
// encompasses the following origins (among others):
//
//	https://foo.example.com
//	https://bar.example.com
//	https://bar.foo.example.com
//	https://baz.bar.foo.example.com
//
// An asterisk in place of a port denotes an arbitrary (possibly implicit)
// port. For instance,
//
//	http://localhost:*
//
// encompasses the following origins (among others):
//
//	http://localhost
//	http://localhost:8080
//	http://localhost:9090
//
// Specifying both arbitrary subdomains and arbitrary ports
// in a given origin pattern is permitted. For instance,
//
//	https://*.example.com:*
//
// encompasses the following origins (among others):
//
//	https://foo.example.com
//	https://foo.example.com:8080
//	https://foo.example.com:9090
//	https://bar.foo.example.com
//	https://bar.foo.example.com:8080
//	https://bar.foo.example.com:9090
//
// No other forms of origin patterns are supported.
//
// Origin patterns whose scheme is not https and whose host is neither localhost
// nor a [loopback IP address] are deemed insecure;
// as such, they are by default prohibited when credentialed access is enabled.
// If, even in such cases,
// you deliberately wish to allow some insecure origins,
// you must also set the [Config.DangerouslyTolerateInsecureOrigins] field.
//
// Allowing arbitrary subdomains of a base domain that happens to be a
// [public suffix] is dangerous; as such, doing so is by default prohibited:
//
//	https://*.example.com // permitted: example.com is not a public suffix
//	https://*.com         // prohibited (by default): com is a public suffix
//	https://*.github.io   // prohibited (by default): github.io is a public suffix
//
// If you deliberately wish to allow arbitrary subdomains of some public
// suffix, you must also set the
// [Config.DangerouslyTolerateSubdomainsOfPublicSuffixes] field.
//
// # Credentialed
//
// Credentialed, when set, configures a CORS middleware to allow
// [credentialed access] (e.g. with [cookies])
// in addition to anonymous access.
//
// Note that credentialed access is required only by requests that carry
// browser-managed credentials
// (as opposed to client-managed credentials, such as [Bearer tokens]).
// In practice, if you wish to allow clients to send requests that carry
// a header of the form
//
//	Authorization: Bearer xyz
//
// to you server, you can likely leave Credentialed unset;
// instead, you should simply allow request-header name "Authorization"
// via the [Config.RequestHeaders] field.
//
// # Methods
//
// Methods configures a CORS middleware to allow any of the specified
// HTTP methods. Method names are case-sensitive.
//
//	Methods: []string{
//	  http.MethodGet,
//	  http.MethodPost,
//	  http.MethodPut,
//	  "PURGE",
//	}
//
// A single asterisk denotes all methods:
//
//	Methods: []string{"*"},
//
// The three so-called "[CORS-safelisted methods]" ([GET], [HEAD], and [POST])
// are by default allowed by the CORS protocol.
// As such, allowing them explicitly in your CORS configuration is
// permitted but never actually necessary.
//
// Moreover, the CORS protocol forbids the use of some method names.
// Accordingly, specifying [forbidden method names] is prohibited.
//
// Note that, contrary to popular belief, specifying OPTIONS as an allowed
// method in your CORS configuration is only required if you wish to allow
// clients to make explicit use of that method, e.g. via the following client
// code:
//
//	fetch('https://example.com', {method: 'OPTIONS'})
//		.then(/* ... */)
//
// In the great majority of cases, specifying OPTIONS as an allowed method
// in your CORS configuration is unnecessary.
//
// # RequestHeaders
//
// RequestHeaders configures a CORS middleware to allow any of the
// specified request headers. Header names are case-insensitive.
//
//	RequestHeaders: []string{"Content-Type"},
//
// When credentialed access is enabled
// (i.e. when the [Config.Credentialed] field is set),
// a single asterisk denotes all request-header names:
//
//	Credentialed:   true,
//	RequestHeaders: []string{"*"}, // allows all request-header names
//
// If you can, you should avoid this conjunction of enabling credentialed access
// and allowing all request-header names; otherwise, middleware performance may
// indeed suffer in the face of some adversarial preflight requests.
//
// For both [technical and security reasons], the asterisk
// has a different meaning when credentialed access is disabled;
// it then denotes all request-header names other than [Authorization]:
//
//	Credentialed:   false,
//	RequestHeaders: []string{"*"}, // allows all request-header names other than Authorization
//
// When credentialed access is disabled, if you wish to allow Authorization
// in addition to all other request-header names,
// you must also explicitly specify that name:
//
//	Credentialed:   false,
//	RequestHeaders: []string{"*", "Authorization"},  // allows all request-header names
//
// The CORS protocol defines a number of so-called
// "[forbidden request-header names]";
// browsers prevent clients from including such headers in their requests.
// Accordingly, specifying one or more [forbidden request-header names]
// is prohibited.
//
// Finally, some header names that have no place in a request are prohibited:
//
//   - Access-Control-Allow-Credentials
//   - Access-Control-Allow-Headers
//   - Access-Control-Allow-Methods
//   - Access-Control-Allow-Origin
//   - Access-Control-Expose-Headers
//   - Access-Control-Max-Age
//
// # MaxAgeInSeconds
//
// MaxAgeInSeconds configures a CORS middleware to instruct browsers
// to cache preflight responses for a duration no longer than
// the specified number of seconds.
//
// The zero value instructs browsers to cache preflight responses with a
// [default max-age value] of five seconds.
// To instruct browsers to eschew caching of preflight responses altogether,
// specify a value of -1. No other negative value is permitted.
//
// Because modern browsers [cap the max-age value],
// this field is subject to an upper bound:
// specifying a value larger than 86400 is prohibited.
//
// # ResponseHeaders
//
// ResponseHeaders configures a CORS middleware to expose the specified
// response headers to clients. Header names are case-insensitive.
//
//	ResponseHeaders: []string{"X-Response-Time"},
//
// When credentialed access is disabled
// (i.e. when the [Config.Credentialed] field is unset),
// a single asterisk denotes all response-header names:
//
//	ResponseHeaders: []string{"*"},
//
// However, for [technical reasons], this is only permitted if the
// [Config.Credentialed] field is unset.
//
// The CORS protocol defines a number of so-called
// "[CORS-safelisted response-header names]",
// which need not be explicitly specified as exposed.
// As such, explicitly specifying them as exposed in your CORS configuration
// is permitted but never actually necessary.
//
// The CORS protocol also defines a number of so-called
// "[forbidden response-header names]",
// which cannot be exposed to clients.
// Accordingly, specifying one or more forbidden response-header name(s) is
// prohibited.
//
// Finally, some header names that have no place in a response are prohibited:
//
//   - Access-Control-Request-Headers
//   - Access-Control-Request-Method
//   - Origin
//
// # DangerouslyTolerateInsecureOrigins
//
// DangerouslyTolerateInsecureOrigins enables you to allow insecure origins
// (i.e. origins whose scheme is not https and whose host is neither localhost
// nor a [loopback IP address]),
// which are by default prohibited when credentialed access is enabled.
//
// Be aware that allowing insecure origins exposes your clients to
// some [active network attacks],
// as described by James Kettle in [the talk he gave at AppSec EU 2017].
//
// # DangerouslyTolerateSubdomainsOfPublicSuffixes
//
// DangerouslyTolerateSubdomainsOfPublicSuffixes enables you to allow all
// subdomains of some [public suffix]
// (also known as "effective top-level domain"),
// which is by default prohibited.
//
// Be aware that allowing all subdomains of a public suffix (e.g. com)
// is dangerous, because such domains are typically registrable by anyone,
// including attackers.
//
// [ASCII serialized form]: https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin
// [Authorization]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
// [Bearer tokens]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication#bearer
// [CORS-safelisted methods]: https://fetch.spec.whatwg.org/#cors-safelisted-method
// [CORS-safelisted response-header names]: https://fetch.spec.whatwg.org/#cors-safelisted-response-header-name
// [GET]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/GET
// [HEAD]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/HEAD
// [POST]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST
// [Web origins]: https://developer.mozilla.org/en-US/docs/Glossary/Origin
// [active network attacks]: https://en.wikipedia.org/wiki/Man-in-the-middle_attack
// [cap the max-age value]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age#delta-seconds
// [compressed form]: https://datatracker.ietf.org/doc/html/rfc5952
// [cookies]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
// [credentialed access]: https://fetch.spec.whatwg.org/#concept-request-credentials-mode
// [cross-origin attacks]: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
// [cross-site scripting]: https://owasp.org/www-community/attacks/xss/
// [default max-age value]: https://fetch.spec.whatwg.org/#http-access-control-max-age
// [dotted-quad notation]: https://en.wikipedia.org/wiki/Dot-decimal_notation
// [forbidden method names]: https://fetch.spec.whatwg.org/#forbidden-method
// [forbidden request-header names]: https://fetch.spec.whatwg.org/#forbidden-request-header
// [forbidden response-header names]: https://fetch.spec.whatwg.org/#forbidden-response-header-name
// [fundamentally unsafe]: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
// [loopback IP address]: https://www.rfc-editor.org/rfc/rfc5735#section-3
// [null origin]: https://fetch.spec.whatwg.org/#append-a-request-origin-header
// [public suffix]: https://publicsuffix.org/
// [security reasons]: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
// [subdomain takeover]: https://labs.detectify.com/writeups/hostile-subdomain-takeover-using-heroku-github-desk-more/
// [technical and security reasons]: https://github.com/whatwg/fetch/issues/251#issuecomment-209265586
// [technical reasons]: https://github.com/rs/cors/issues/79#issuecomment-1694622148
// [the talk he gave at AppSec EU 2017]: https://www.youtube.com/watch?v=wgkj4ZgxI4c&t=1305s
type Config struct {
	// Precludes comparability, unkeyed struct literals, and conversion to and
	// from third-party types.
	_ [0]func()

	Origins                                       []string
	Credentialed                                  bool
	Methods                                       []string
	RequestHeaders                                []string
	MaxAgeInSeconds                               int
	ResponseHeaders                               []string
	DangerouslyTolerateInsecureOrigins            bool
	DangerouslyTolerateSubdomainsOfPublicSuffixes bool
}

type internalConfig struct {
	tree                         origins.Tree // tree.IsEmpty() <=> any origin allowed
	aceh                         string
	allowedMethods               util.Set       // allowedMethods.Size() > 0 => !allowAnyMethod
	allowedReqHdrs               util.SortedSet // allowedReqHdrs.Size() > 0 => !asteriskReqHdrs
	acah                         []string
	credentialed                 bool // tree.IsEmpty() => !credentialed
	allowAnyMethod               bool
	asteriskReqHdrs              bool
	allowAuthorization           bool
	tolerateSubsOfPublicSuffixes bool
	tolerateInsecureOrigins      bool
	preflight                    bool // reports whether preflight may succeed
	acma                         []string
}

func newInternalConfig(cfg *Config) (*internalConfig, error) {
	if cfg == nil {
		return nil, nil
	}
	icfg := internalConfig{
		credentialed:                 cfg.Credentialed,
		tolerateInsecureOrigins:      cfg.DangerouslyTolerateInsecureOrigins,
		tolerateSubsOfPublicSuffixes: cfg.DangerouslyTolerateSubdomainsOfPublicSuffixes,
	}

	// Accumulate errors in a slice so as to call errors.Join at most once,
	// for better performance.
	errs := icfg.validateOriginPatterns(cfg.Origins)
	errs = icfg.validateMethods(errs, cfg.Methods)
	errs = icfg.validateRequestHeaders(errs, cfg.RequestHeaders)
	errs = icfg.validateMaxAge(errs, cfg.MaxAgeInSeconds)
	errs = icfg.validateResponseHeaders(errs, cfg.ResponseHeaders)

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	icfg.preflight = icfg.allowAnyMethod ||
		icfg.allowedMethods.Size() > 0 ||
		icfg.asteriskReqHdrs ||
		icfg.allowAuthorization ||
		icfg.allowedReqHdrs.Size() > 0
	return &icfg, nil
}

func (icfg *internalConfig) validateOriginPatterns(rawPatterns []string) []error {
	if len(rawPatterns) == 0 {
		err := &cfgerrors.UnacceptableOriginPatternError{
			Reason: "missing",
		}
		return []error{err}
	}
	var (
		ps             []*origins.Pattern
		allowAnyOrigin bool
		errs           []error
	)
	for _, raw := range rawPatterns {
		if raw == headers.ValueWildcard {
			if icfg.credentialed {
				err := &cfgerrors.IncompatibleOriginPatternError{
					Value:  headers.ValueWildcard,
					Reason: "credentialed",
				}
				errs = append(errs, err)
				continue
			}
			if allowAnyOrigin {
				continue
			}
			allowAnyOrigin = true
			// We no longer need to maintain a set of allowed origins.
			icfg.tree = origins.Tree{}
			continue
		}
		pattern, err := origins.ParsePattern(raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !icfg.tolerateInsecureOrigins &&
			icfg.credentialed &&
			pattern.IsDeemedInsecure() {
			// We require DangerouslyTolerateInsecureOrigins to be set only if
			//  - enable credentialed access, and
			//  - users specify one or more insecure origin patterns.
			//
			// In all other cases, insecure origins like http://example.com are
			// indeed no less insecure than origin pattern "*" is, which itself
			// doesn't require DangerouslyTolerateInsecureOrigins to be set.
			err := &cfgerrors.IncompatibleOriginPatternError{
				Value:  raw,
				Reason: "credentialed",
			}
			errs = append(errs, err)
			continue
		}
		if !icfg.tolerateSubsOfPublicSuffixes &&
			pattern.Kind == origins.ArbitrarySubdomains &&
			pattern.HostIsEffectiveTLD() {
			err := &cfgerrors.IncompatibleOriginPatternError{
				Value:  raw,
				Reason: "psl",
			}
			errs = append(errs, err)
			continue
		}
		if !allowAnyOrigin {
			ps = append(ps, &pattern)
		}
	}
	if !allowAnyOrigin {
		icfg.tree = origins.NewTree(ps...)
	}
	return errs
}

func (icfg *internalConfig) validateMethods(errs []error, names []string) []error {
	for _, name := range names {
		if name == headers.ValueWildcard {
			if icfg.allowAnyMethod {
				continue
			}
			// We no longer need to maintain a set of allowed methods.
			icfg.allowedMethods = util.Set{}
			icfg.allowAnyMethod = true
			continue
		}
		if !methods.IsValid(name) {
			err := &cfgerrors.UnacceptableMethodError{
				Value:  name,
				Reason: "invalid",
			}
			errs = append(errs, err)
			continue
		}
		name = methods.Normalize(name)
		if methods.IsSafelisted(name) {
			// Safelisted methods need not be explicitly allowed;
			// see https://stackoverflow.com/a/71429784/2541573.
			continue
		}
		if methods.IsForbidden(name) {
			err := &cfgerrors.UnacceptableMethodError{
				Value:  name,
				Reason: "forbidden",
			}
			errs = append(errs, err)
			continue
		}
		if !icfg.allowAnyMethod {
			icfg.allowedMethods.Add(name)
		}
	}
	return errs
}

func (icfg *internalConfig) validateRequestHeaders(errs []error, names []string) []error {
	if len(names) == 0 {
		return errs
	}
	var (
		allowedHeaders util.SortedSet
		nbErrors       = len(errs)
	)
	for _, name := range names {
		if name == headers.ValueWildcard {
			if icfg.asteriskReqHdrs {
				continue
			}
			icfg.asteriskReqHdrs = true
			// We no longer need to maintain a set of allowed headers.
			allowedHeaders = util.SortedSet{}
			continue
		}
		if !headers.IsValid(name) {
			err := &cfgerrors.UnacceptableHeaderNameError{
				Value:  name,
				Type:   "request",
				Reason: "invalid",
			}
			errs = append(errs, err)
			continue
		}
		// Fetch-compliant browsers byte-lowercase header names
		// before writing them to the ACRH header; see
		// https://fetch.spec.whatwg.org/#cors-unsafe-request-header-names,
		// step 6.
		normalized := strings.ToLower(name)
		if normalized == headers.Authorization {
			if icfg.allowAuthorization {
				continue
			}
			icfg.allowAuthorization = true
			if !(icfg.credentialed && icfg.asteriskReqHdrs) {
				// According to the Fetch standard, the wildcard does not cover
				// request-header name Authorization; see
				// https://fetch.spec.whatwg.org/#cors-non-wildcard-request-header-name
				// and https://github.com/whatwg/fetch/issues/251#issuecomment-209265586.
				allowedHeaders.Add(normalized)
			}
			continue
		}
		// Note: at this stage, normalized is other than "authorization".
		if headers.IsForbiddenRequestHeaderName(normalized) {
			err := &cfgerrors.UnacceptableHeaderNameError{
				Value:  name,
				Type:   "request",
				Reason: "forbidden",
			}
			errs = append(errs, err)
			continue
		}
		if headers.IsProhibitedRequestHeaderName(normalized) {
			err := &cfgerrors.UnacceptableHeaderNameError{
				Value:  name,
				Type:   "request",
				Reason: "prohibited",
			}
			errs = append(errs, err)
			continue
		}
		if !icfg.asteriskReqHdrs {
			allowedHeaders.Add(normalized)
		}
	}
	if len(errs) > nbErrors {
		return errs
	}
	switch {
	case icfg.asteriskReqHdrs && !icfg.credentialed:
		if icfg.allowAuthorization {
			// According to the Fetch standard, the wildcard does not cover
			// request-header name Authorization; see
			// https://fetch.spec.whatwg.org/#cors-non-wildcard-request-header-name
			// and https://github.com/whatwg/fetch/issues/251#issuecomment-209265586.
			//
			// Note that we systematically list Authorization
			// in the ACAH header here.
			// Unfortunately, such an approach reveals that
			// the CORS configuration allows this request-header name,
			// even to (potentially malicious) clients that don't include
			// an Authorization header in their requests.
			//
			// An alternative approach would consist in replying
			// with "*,authorization" when ACRH contains "authorization",
			// and with "*" when ACRH does not contain "authorization".
			// However, such an approach would require us to scan the entire
			// ACRH header in search of "authorization",
			// which, in the event of a long ACRH header, would be costly
			// in CPU cycles.
			// Adversaries aware of this subtlety could spoof preflight requests
			// containing a maliciously long ACRH header in order to exercise
			// this costly execution path and thereby generate undue load
			// on the server.
			icfg.acah = headers.WildcardAuthSgl
		} else {
			icfg.acah = headers.WildcardSgl
		}
	case allowedHeaders.Size() > 0:
		icfg.allowedReqHdrs = allowedHeaders
		s := allowedHeaders.ToSlice()
		// The elements of a header-field value may be separated simply by commas;
		// since whitespace is optional, let's not use any.
		// See https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#abnf.extension.recipient
		icfg.acah = []string{strings.Join(s, headers.ValueSep)}
	}
	return errs
}

func (icfg *internalConfig) validateMaxAge(errs []error, delta int) []error {
	const (
		// see https://fetch.spec.whatwg.org/#cors-preflight-fetch-0, step 7.9
		defaultMaxAge = 5
		// Current upper bounds:
		//  - Firefox: 86400 (24h)
		//  - Chromium: 7200 (2h)
		//  - WebKit/Safari: 600 (10m)
		//
		// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age#delta-seconds.
		upperBound = 86400
		// sentinel value for disabling preflight caching
		disableCaching = -1
	)
	switch {
	case delta < disableCaching || upperBound < delta:
		err := &cfgerrors.MaxAgeOutOfBoundsError{
			Value:   delta,
			Default: defaultMaxAge,
			Max:     upperBound,
			Disable: disableCaching,
		}
		return append(errs, err)
	case delta == disableCaching:
		icfg.acma = []string{"0"}
		return errs
	case delta == 0:
		return errs
	default:
		icfg.acma = []string{strconv.Itoa(delta)}
		return errs
	}
}

func (icfg *internalConfig) validateResponseHeaders(errs []error, names []string) []error {
	if len(names) == 0 {
		return errs
	}
	var (
		exposedHeaders   util.Set
		exposeAllResHdrs bool
		nbErrors         = len(errs)
	)
	for _, name := range names {
		if name == headers.ValueWildcard {
			if icfg.credentialed {
				// Exposing response headers while also allowing credentialed
				// access requires listing all those response headers' names in
				// the ACEH header. To do so, middleware would first have to
				// somehow compile a list of those names, including the ones
				// (if any) added by the wrapped handler. Compiling such a list
				// would require wrapping the http.ResponseWriter type, which
				// would have the undesirable effect of masking any of that
				// type's "optional interfaces" (i.e. its interface subtypes);
				// see https://blog.merovius.de/posts/2017-07-30-the-trouble-with-optional-interfaces/.
				//
				// Therefore, exposing all response headers while also allowing
				// credentialed access isn't viable.
				err := new(cfgerrors.IncompatibleWildcardResponseHeaderNameError)
				errs = append(errs, err)
				continue
			}
			if exposeAllResHdrs {
				continue
			}
			exposeAllResHdrs = true
			// We no longer need to maintain a set of exposed headers.
			exposedHeaders = util.Set{}
			continue
		}
		if !headers.IsValid(name) {
			err := &cfgerrors.UnacceptableHeaderNameError{
				Value:  name,
				Type:   "response",
				Reason: "invalid",
			}
			errs = append(errs, err)
			continue
		}
		normalized := strings.ToLower(name)
		if headers.IsForbiddenResponseHeaderName(normalized) {
			err := &cfgerrors.UnacceptableHeaderNameError{
				Value:  name,
				Type:   "response",
				Reason: "forbidden",
			}
			errs = append(errs, err)
			continue
		}
		if headers.IsProhibitedResponseHeaderName(normalized) {
			err := &cfgerrors.UnacceptableHeaderNameError{
				Value:  name,
				Type:   "response",
				Reason: "prohibited",
			}
			errs = append(errs, err)
			continue
		}
		if headers.IsSafelistedResponseHeaderName(normalized) {
			// silently tolerate safelisted response-header names
			continue
		}
		if !exposeAllResHdrs {
			exposedHeaders.Add(normalized)
		}
	}
	if len(errs) > nbErrors {
		return errs
	}
	switch {
	case exposeAllResHdrs:
		icfg.aceh = headers.ValueWildcard
	case exposedHeaders.Size() > 0:
		// The elements of a header-field value may be separated simply by commas;
		// since whitespace is optional, let's not use any.
		// See https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#abnf.extension.recipient
		icfg.aceh = strings.Join(exposedHeaders.ToSlice(), headers.ValueSep)
	}
	return errs
}

const (
	// According to the Fetch standard, any 2xx status code is acceptable
	// to mark a preflight response as successful.
	// Arguably, 204 (No Content) is the most appropriate status code.
	// However, some rare non-compliant user agents fail preflight when the
	// preflight response has a status code other than 200 (e.g. 204). Oh well.
	preflightOKStatus   = http.StatusNoContent
	preflightFailStatus = http.StatusForbidden
)

// newConfig returns a Config on the basis of icfg.
// The soundness of the result is guaranteed only if icfg is the result of a
// previous call to newInternalConfig.
func newConfig(icfg *internalConfig) *Config {
	if icfg == nil {
		return nil
	}

	cfg := Config{
		Credentialed:                                  icfg.credentialed,
		DangerouslyTolerateInsecureOrigins:            icfg.tolerateInsecureOrigins,
		DangerouslyTolerateSubdomainsOfPublicSuffixes: icfg.tolerateSubsOfPublicSuffixes,
	}

	// Note: do not hold (in cfg) any references to mutable fields of icfg;
	// use defensive copying if required.

	// origins
	if icfg.tree.IsEmpty() {
		cfg.Origins = []string{headers.ValueWildcard}
	} else {
		cfg.Origins = slices.Collect(icfg.tree.Elems())
	}

	// response headers
	if len(icfg.aceh) > 0 {
		cfg.ResponseHeaders = strings.Split(icfg.aceh, headers.ValueSep)
	}

	if !icfg.preflight {
		return &cfg
	}

	// methods
	switch {
	case icfg.allowAnyMethod:
		cfg.Methods = []string{headers.ValueWildcard}
	case icfg.allowedMethods.Size() > 0:
		cfg.Methods = icfg.allowedMethods.ToSlice()
	}

	// request headers
	switch {
	case !icfg.credentialed && icfg.asteriskReqHdrs && icfg.allowAuthorization:
		cfg.RequestHeaders = []string{headers.ValueWildcard, headers.Authorization}
	case icfg.asteriskReqHdrs:
		cfg.RequestHeaders = []string{headers.ValueWildcard}
	case icfg.allowedReqHdrs.Size() > 0:
		cfg.RequestHeaders = icfg.allowedReqHdrs.ToSlice()
	}

	// max age
	if len(icfg.acma) > 0 {
		maxAge, _ := strconv.Atoi(icfg.acma[0]) // safe, by construction
		if maxAge != 0 {
			cfg.MaxAgeInSeconds = maxAge
		} else {
			cfg.MaxAgeInSeconds = -1
		}
	}

	return &cfg
}
