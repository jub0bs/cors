package cors

import (
	"errors"
	"net/http"
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
// Malicious actors, by exploiting some Web vulnerabilities (including
// [cross-site scripting] and [subdomain takeover]) on those origins,
// may be able to gain a foothold on those origins
// and mount [cross-origin attacks] against your users from there.
// Therefore, you should (in general) exercise caution when deciding which
// origins to allow. In particular, if you enable [credentialed access],
// you should only allow Web origins you absolutely trust.
//
// Omitting to specify at least one origin pattern is prohibited;
// so is specifying one or more invalid or prohibited origin pattern(s).
//
// All valid schemes (no longer than 64 bytes) other than file are permitted,
// with one caveat about schemes other than https explained further down:
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
//	https://example.com       // permitted (no port)
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
// denotes exactly one arbitrary DNS label
// or several period-separated arbitrary DNS labels.
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
// you must also set the ExtraConfig.DangerouslyTolerateInsecureOrigins field.
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
// ExtraConfig.DangerouslyTolerateSubdomainsOfPublicSuffixes field.
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
// via the RequestHeaders field.
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
// Note that, contrary to popular belief, listing OPTIONS as an allowed method
// in your CORS configuration is only required if you wish to allow clients
// to make explicit use of that method, e.g. via the following client code:
//
//	fetch('https://example.com', {method: 'OPTIONS'})
//
// In the great majority of cases, listing OPTIONS as an allowed method
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
// (i.e. when the Credentialed field is set),
// a single asterisk denotes all request-header names:
//
//	Credentialed:   true,
//	RequestHeaders: []string{"*"}, // allows all request-header names
//
// If you can, you should avoid this conjunction of enabling credentialed access
// and allowing all request-header names; otherwise, middleware performance may
// indeed suffer in the face of some adversarial preflight requests.
//
// For both technical and security reasons, the asterisk
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
// Because modern browsers [cap the max-age value]
// (the highest cap currently is Firefox's: 86,400 seconds),
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
// (i.e. when the Credentialed field is unset),
// a single asterisk denotes all response-header names:
//
//	ResponseHeaders: []string{"*"},
//
// However, for technical reasons, this is only permitted if the Credentialed
// field is unset.
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
// [ASCII serialized form]: https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin
// [Authorization]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
// [Bearer tokens]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication#bearer
// [CORS-safelisted methods]: https://fetch.spec.whatwg.org/#cors-safelisted-method
// [CORS-safelisted response-header names]: https://fetch.spec.whatwg.org/#cors-safelisted-response-header-name
// [GET]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/GET
// [HEAD]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/HEAD
// [POST]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST
// [Web origins]: https://developer.mozilla.org/en-US/docs/Glossary/Origin
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
type Config struct {
	_ [0]func() // precludes comparability and unkeyed struct literals

	Origins         []string
	Credentialed    bool
	Methods         []string
	RequestHeaders  []string
	MaxAgeInSeconds int
	ResponseHeaders []string
	ExtraConfig
}

// An ExtraConfig provides more advanced (and potentially dangerous)
// configuration settings.
//
// # PreflightSuccessStatus
//
// PreflightSuccessStatus configures a CORS middleware to use the specified
// status code in successful preflight responses.
// The default status code, which is used if this field has the zero value,
// is [204].
//
// Specifying a non-zero status code outside the [2xx range] is prohibited.
//
// According to [the Fetch standard], any 2xx status code is acceptable
// to mark a prelight response as successful;
// however, some rare non-compliant user agents fail preflight when the
// preflight response has a status code other than 200 (e.g. 204).
// If some of your clients rely on such non-compliant user agents,
// you should set a custom preflight-success status of 200.
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
// [204]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/204
// [2xx range]: https://fetch.spec.whatwg.org/#ok-status
// [active network attacks]: https://en.wikipedia.org/wiki/Man-in-the-middle_attack
// [loopback IP address]: https://www.rfc-editor.org/rfc/rfc5735#section-3
// [public suffix]: https://publicsuffix.org/
// [the Fetch standard]: https://fetch.spec.whatwg.org
// [the talk he gave at AppSec EU 2017]: https://www.youtube.com/watch?v=wgkj4ZgxI4c&t=1305s
//
// [Same-Origin Policy]: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
// [no-cors mode]: https://fetch.spec.whatwg.org/#concept-request-mode
type ExtraConfig struct {
	_ [0]func() // precludes comparability and unkeyed struct literals

	PreflightSuccessStatus                        int
	DangerouslyTolerateInsecureOrigins            bool
	DangerouslyTolerateSubdomainsOfPublicSuffixes bool
}

type internalConfig struct {
	tree                    origins.Tree // empty means all origins allowed
	allowedMethods          util.Set
	allowedReqHdrs          util.SortedSet
	acah                    []string
	preflightStatusMinus200 uint8 // range: [0,99]
	credentialed            bool
	allowAnyMethod          bool
	asteriskReqHdrs         bool
	allowAuthorization      bool
	subsOfPublicSuffixes    bool
	insecureOrigins         bool
	acma                    []string
	aceh                    string
}

func newInternalConfig(cfg *Config) (*internalConfig, error) {
	if cfg == nil {
		return nil, nil
	}
	var (
		icfg internalConfig
		errs []error
	)

	// extra config (accessed by other validateX methods)
	if err := icfg.validatePreflightStatus(cfg.PreflightSuccessStatus); err != nil {
		errs = append(errs, err)
	}
	icfg.insecureOrigins = cfg.DangerouslyTolerateInsecureOrigins
	icfg.subsOfPublicSuffixes = cfg.DangerouslyTolerateSubdomainsOfPublicSuffixes

	// base config
	icfg.credentialed = cfg.Credentialed // accessed by other validateX methods
	if err := icfg.validateOrigins(cfg.Origins); err != nil {
		errs = append(errs, err)
	}
	if err := icfg.validateMethods(cfg.Methods); err != nil {
		errs = append(errs, err)
	}
	if err := icfg.validateRequestHeaders(cfg.RequestHeaders); err != nil {
		errs = append(errs, err)
	}
	if err := icfg.validateMaxAge(cfg.MaxAgeInSeconds); err != nil {
		errs = append(errs, err)
	}
	if err := icfg.validateResponseHeaders(cfg.ResponseHeaders); err != nil {
		errs = append(errs, err)
	}

	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}
	return &icfg, nil
}

func (icfg *internalConfig) validateOrigins(patterns []string) error {
	if len(patterns) == 0 {
		err := &cfgerrors.UnacceptableOriginPatternError{
			Reason: "missing",
		}
		return err
	}
	var (
		tree           origins.Tree
		discreteOrigin string
		errs           []error
		allowAnyOrigin bool
	)
	for _, raw := range patterns {
		if raw == headers.ValueWildcard {
			if icfg.credentialed {
				err := &cfgerrors.IncompatibleOriginPatternError{
					Value:  "*",
					Reason: "credentialed",
				}
				errs = append(errs, err)
			}
			allowAnyOrigin = true
			continue
		}
		pattern, err := origins.ParsePattern(raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if pattern.IsDeemedInsecure() && !icfg.insecureOrigins {
			// We require ExtraConfig.DangerouslyTolerateInsecureOrigins to
			// be set only when
			// - users specify one or more insecure origin patterns, and
			// - enable credentialed access.
			// In all other cases, insecure origins like http://example.com are
			// indeed no less insecure than * is, which itself doesn't require
			// ExtraConfig.DangerouslyTolerateInsecureOrigins to be set.
			if icfg.credentialed {
				err := &cfgerrors.IncompatibleOriginPatternError{
					Value:  raw,
					Reason: "credentialed",
				}
				errs = append(errs, err)
			}
		}
		if pattern.Kind != origins.PatternKindSubdomains && discreteOrigin == "" {
			discreteOrigin = raw
		}
		if pattern.Kind == origins.PatternKindSubdomains && !icfg.subsOfPublicSuffixes {
			if _, isEffectiveTLD := pattern.HostIsEffectiveTLD(); isEffectiveTLD {
				err := &cfgerrors.IncompatibleOriginPatternError{
					Value:  raw,
					Reason: "psl",
				}
				errs = append(errs, err)
			}
		}
		tree.Insert(&pattern)
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	if allowAnyOrigin {
		return nil
	}
	icfg.tree = tree
	return nil
}

func (icfg *internalConfig) validateMethods(names []string) error {
	if len(names) == 0 {
		return nil
	}
	var (
		allowedMethods util.Set
		errs           []error
	)
	for _, name := range names {
		if name == headers.ValueWildcard {
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
		allowedMethods.Add(name)
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	if icfg.allowAnyMethod {
		return nil
	}
	icfg.allowedMethods = allowedMethods
	return nil
}

func (icfg *internalConfig) validateRequestHeaders(names []string) error {
	if len(names) == 0 {
		return nil
	}
	var (
		allowedHeaders util.SortedSet
		errs           []error
	)
	for _, name := range names {
		if name == headers.ValueWildcard {
			icfg.asteriskReqHdrs = true
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
			if !icfg.asteriskReqHdrs || !icfg.credentialed {
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
		allowedHeaders.Add(normalized)
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	if !icfg.asteriskReqHdrs && allowedHeaders.Size() != 0 {
		icfg.allowedReqHdrs = allowedHeaders
		s := allowedHeaders.ToSlice()
		// The elements of a header-field value may be separated simply by commas;
		// since whitespace is optional, let's not use any.
		// See https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#abnf.extension.recipient
		icfg.acah = []string{strings.Join(s, headers.ValueSep)}
	}
	return nil
}

func (icfg *internalConfig) validateMaxAge(delta int) error {
	const (
		// see https://fetch.spec.whatwg.org/#cors-preflight-fetch-0, step 7.9
		defaultMaxAge = 5
		// Current upper bounds:
		//  - Firefox: 86400 (24h)
		//  - Chromium: 7200 (2h)
		//  - WebKit/Safari: 600 (10m)
		// see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age#delta-seconds
		upperBound = 86400
		// sentinel value for disabling preflight caching
		disableCaching = -1
	)
	switch {
	case delta < disableCaching || upperBound < delta:
		return &cfgerrors.MaxAgeOutOfBoundsError{
			Value:   delta,
			Default: defaultMaxAge,
			Max:     upperBound,
			Disable: disableCaching,
		}
	case delta == disableCaching:
		icfg.acma = []string{"0"}
		return nil
	case delta == 0:
		return nil
	default:
		icfg.acma = []string{strconv.Itoa(delta)}
		return nil
	}
}

func (icfg *internalConfig) validateResponseHeaders(names []string) error {
	if len(names) == 0 {
		return nil
	}
	var (
		exposedHeaders   util.Set
		errs             []error
		exposeAllResHdrs bool
	)
	for _, name := range names {
		if name == headers.ValueWildcard {
			if icfg.credentialed {
				err := new(cfgerrors.IncompatibleWildcardResponseHeaderNameError)
				errs = append(errs, err)
			}
			exposeAllResHdrs = true
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
		exposedHeaders.Add(normalized)
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
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
	return nil
}

func (icfg *internalConfig) validatePreflightStatus(status int) error {
	if status == 0 {
		icfg.preflightStatusMinus200 = defaultPreflightStatus - 200
		return nil
	}
	const ( // see https://fetch.spec.whatwg.org/#ok-status
		lowerBound = 200
		upperBound = 299
	)
	if !(lowerBound <= status && status <= upperBound) {
		return &cfgerrors.PreflightSuccessStatusOutOfBoundsError{
			Value:   status,
			Default: defaultPreflightStatus,
			Min:     lowerBound,
			Max:     upperBound,
		}
	}
	icfg.preflightStatusMinus200 = uint8(status - 200) // 200 <= status < 300
	return nil
}

const defaultPreflightStatus = http.StatusNoContent

// newConfig returns a Config on the basis of icfg.
// The soundness of the result is guaranteed only if icfg is the result of a
// previous call to newInternalConfig.
func newConfig(icfg *internalConfig) *Config {
	if icfg == nil {
		return nil
	}
	// Note: do not hold (in cfg) any references to mutable fields of icfg;
	// use defensive copying if required.
	var cfg Config

	// origins
	if icfg.tree.IsEmpty() {
		cfg.Origins = []string{"*"}
	} else {
		cfg.Origins = icfg.tree.Elems()
	}

	// credentialed
	cfg.Credentialed = icfg.credentialed

	// methods
	switch {
	case icfg.allowAnyMethod:
		cfg.Methods = []string{"*"}
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
		maxAge, _ := strconv.Atoi(icfg.acma[0]) // safe by construction of internalConfig
		if maxAge != 0 {
			cfg.MaxAgeInSeconds = maxAge
		} else {
			cfg.MaxAgeInSeconds = -1
		}
	}

	// response headers
	if len(icfg.aceh) > 0 {
		cfg.ResponseHeaders = strings.Split(icfg.aceh, headers.ValueSep)
	}

	// extra config
	if icfg.preflightStatusMinus200+200 != defaultPreflightStatus {
		cfg.ExtraConfig.PreflightSuccessStatus = int(icfg.preflightStatusMinus200) + 200
	}
	cfg.ExtraConfig.DangerouslyTolerateInsecureOrigins = icfg.insecureOrigins
	cfg.ExtraConfig.DangerouslyTolerateSubdomainsOfPublicSuffixes = icfg.subsOfPublicSuffixes
	return &cfg
}
