package cors

import (
	"errors"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

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
// origins to allow. In particular,
// if you enable [credentialed access] and/or [Private-Network Access],
// you should only allow Web origins you absolutely trust.
//
// Omitting to specify at least one origin pattern is prohibited;
// so is specifying one or more invalid or prohibited origin pattern(s).
//
// Permitted schemes are limited to http
// (with one caveat explained further down)
// and https; specifying origin patterns with other schemes is prohibited:
//
//	http://example.com             // permitted
//	https://example.com            // permitted
//	chrome-extension://example.com // prohibited
//
// Origins must be specified in [ASCII serialized form]; Unicode is prohibited:
//
//	https://example.com            // permitted
//	https://www.xn--xample-9ua.com // permitted (Punycode)
//	https://www.résumé.com         // prohibited (Unicode)
//
// Because it's [fundamentally unsafe], the [null origin] is prohibited.
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
// Specifying origin patterns in addition to the single-asterisk
// origin pattern is prohibited:
//
//	Origins: []string{"*", "https://example.com"}, // prohibited
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
// encompasses the following origins (among others),
//
//	http://localhost
//	http://localhost:80
//	http://localhost:9090
//
// Specifying both arbitrary subdomains and arbitrary ports
// in a given origin pattern is prohibited:
//
//	https://*.example.com      // permitted
//	https://*.example.com:9090 // permitted
//	https://example.com:*      // permitted
//	https://*.example.com:*    // prohibited
//
// No other forms of origin patterns are supported.
//
// Origin patterns whose scheme is http and whose host is neither localhost
// nor a [loopback IP address] are deemed insecure;
// as such, they are by default prohibited when credentialed access and/or
// some form of [Private-Network Access] is enabled.
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
// Specifying methods in addition to the asterisk is prohibited:
//
//	Methods: []string{"*", "POST"}, // prohibited
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
// Specifying request-header names other than Authorization in addition
// to the asterisk is prohibited:
//
//	RequestHeaders: []string{"*", "Foo"},                  // prohibited
//	RequestHeaders: []string{"*", "Authorization", "Foo"}, // prohibited
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
//   - Access-Control-Allow-Private-Network
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
// Specifying response-header names in addition to the asterisk is prohibited:
//
//	ResponseHeaders: []string{"*", "X-Response-Time"}, // prohibited
//
// The CORS protocol defines a number of so-called
// "[CORS-safelisted response-header names]",
// which need not be explicitly specified as exposed.
// The CORS protocol also defines a number of so-called
// "[forbidden response-header names]",
// which cannot be exposed to clients.
// Accordingly, specifying one or more safelisted or forbidden response-header
// name(s) is prohibited.
//
// Finally, some header names that have no place in a response are prohibited:
//
//   - Access-Control-Request-Headers
//   - Access-Control-Request-Method
//   - Access-Control-Request-Private-Network
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
// [Private-Network Access]: https://wicg.github.io/private-network-access/
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
// Setting a custom preflight-success status is useful
// when some of your clients choke on preflight responses that are meant
// to be successful but have a 2xx status code other than 200.
//
// # PrivateNetworkAccess
//
// PrivateNetworkAccess configures a CORS middleware to enable
// [Private-Network Access], which is a W3C initiative that
// strengthens the [Same-Origin Policy] by denying clients
// in more public networks (e.g. the public Internet) access
// to less public networks (e.g. localhost)
// and provides a server-side opt-in mechanism for allowing such access.
//
// This setting applies to all the origins allowed in the configuration
// of the desired middleware.
//
// For [security reasons], PrivateNetworkAccess cannot be set when the
// single-asterisk origin pattern is specified in the Config.Origins field.
//
// At most one of PrivateNetworkAccess and PrivateNetworkAccessInNoCORSModeOnly
// can be set.
//
// # PrivateNetworkAccessInNoCORSModeOnly
//
// PrivateNetworkAccessInNoCORSModeOnly configures a CORS middleware to
// enable [Private-Network Access] in [no-cors mode] only.
// One use case for this setting is given in the
// [link-shortening-service example] of the Private-Network Access draft.
//
// For [security reasons], PrivateNetworkAccessInNoCORSModeOnly cannot be set
// when the single-asterisk origin pattern is specified
// in the Config.Origins field.
//
// At most one of PrivateNetworkAccess and PrivateNetworkAccessInNoCORSModeOnly
// can be set.
//
// # DangerouslyTolerateInsecureOrigins
//
// DangerouslyTolerateInsecureOrigins enables you to allow insecure origins
// (i.e. origins whose scheme is http),
// which are by default prohibited when credentialed access and/or
// some form of [Private-Network Access] is enabled.
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
// [Private-Network Access]: https://wicg.github.io/private-network-access/
// [Same-Origin Policy]: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
// [active network attacks]: https://en.wikipedia.org/wiki/Man-in-the-middle_attack
// [link-shortening-service example]: https://wicg.github.io/private-network-access/#shortlinks
// [no-cors mode]: https://fetch.spec.whatwg.org/#concept-request-mode
// [public suffix]: https://publicsuffix.org/
// [security reasons]: https://developer.chrome.com/blog/private-network-access-preflight/#no-cors-mode
// [the talk he gave at AppSec EU 2017]: https://www.youtube.com/watch?v=wgkj4ZgxI4c&t=1305s
type ExtraConfig struct {
	_ [0]func() // precludes comparability and unkeyed struct literals

	PreflightSuccessStatus                        int
	PrivateNetworkAccess                          bool
	PrivateNetworkAccessInNoCORSModeOnly          bool
	DangerouslyTolerateInsecureOrigins            bool
	DangerouslyTolerateSubdomainsOfPublicSuffixes bool
}

// internal config
type config struct {
	// origins
	corpus         origins.Corpus
	allowAnyOrigin bool

	// credentialed
	credentialed bool

	// methods
	allowedMethods util.Set[string]
	allowAnyMethod bool

	// request headers
	acah               []string
	allowedReqHdrs     util.SortedSet
	asteriskReqHdrs    bool
	allowAuthorization bool

	// max age
	acma []string

	// response headers
	aceh             string
	exposeAllResHdrs bool

	// misc
	debug                      atomic.Bool
	preflightStatus            int
	tmp                        *tmpConfig
	privateNetworkAccess       bool
	privateNetworkAccessNoCors bool
}

type tmpConfig struct {
	publicSuffixes         []string
	insecureOriginPatterns []string
	exposedResHdrs         []string
	subsOfPublicSuffixes   bool
	insecureOrigins        bool
}

func newConfig(c *Config) (*config, error) {
	cfg := config{
		tmp: new(tmpConfig),
	}
	var errs []error

	// base config
	if err := cfg.validateOrigins(c.Origins); err != nil {
		errs = append(errs, err)
	}
	cfg.credentialed = c.Credentialed
	if err := cfg.validateMethods(c.Methods); err != nil {
		errs = append(errs, err)
	}
	if err := cfg.validateRequestHeaders(c.RequestHeaders); err != nil {
		errs = append(errs, err)
	}
	if err := cfg.validateMaxAge(c.MaxAgeInSeconds); err != nil {
		errs = append(errs, err)
	}
	if err := cfg.validateResponseHeaders(c.ResponseHeaders); err != nil {
		errs = append(errs, err)
	}

	// extra config
	if err := cfg.validatePreflightStatus(c.PreflightSuccessStatus); err != nil {
		errs = append(errs, err)
	}
	cfg.privateNetworkAccess = c.PrivateNetworkAccess
	cfg.privateNetworkAccessNoCors = c.PrivateNetworkAccessInNoCORSModeOnly
	cfg.tmp.insecureOrigins = c.DangerouslyTolerateInsecureOrigins
	cfg.tmp.subsOfPublicSuffixes = c.DangerouslyTolerateSubdomainsOfPublicSuffixes

	// validate config as a whole
	if err := cfg.validate(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}

	// precompute ACAH if discrete request headers are allowed (without *)
	if cfg.allowedReqHdrs.Size() != 0 {
		// The elements of a header-field value may be separated simply by commas;
		// since whitespace is optional, let's not use any.
		// See https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#abnf.extension.recipient
		cfg.acah = []string{cfg.allowedReqHdrs.String()}
	}

	// precompute ACEH
	switch {
	case cfg.exposeAllResHdrs:
		cfg.aceh = headers.ValueWildcard
	case len(cfg.tmp.exposedResHdrs) != 0:
		cfg.aceh = strings.Join(cfg.tmp.exposedResHdrs, headers.ValueSep)
	}

	// tmp is no longer needed; let's make it eligible to GC
	cfg.tmp = nil

	return &cfg, nil
}

func (cfg *config) validateOrigins(patterns []string) error {
	if len(patterns) == 0 {
		const msg = "at least one origin pattern must be specified"
		return util.NewError(msg)
	}
	var (
		originPatterns         = make([]origins.Pattern, 0, len(patterns))
		publicSuffixes         []string
		insecureOriginPatterns []string
		discreteOrigin         string
	)
	var errs []error
	for _, raw := range patterns {
		if raw == headers.ValueWildcard {
			cfg.allowAnyOrigin = true
			continue
		}
		pattern, err := origins.ParsePattern(raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if pattern.IsDeemedInsecure() {
			insecureOriginPatterns = append(insecureOriginPatterns, raw)
		}
		if pattern.Kind != origins.PatternKindSubdomains && discreteOrigin == "" {
			discreteOrigin = raw
		}
		if pattern.Kind == origins.PatternKindSubdomains {
			if _, isEffectiveTLD := pattern.HostIsEffectiveTLD(); isEffectiveTLD {
				publicSuffixes = append(publicSuffixes, raw)
			}
		}
		originPatterns = append(originPatterns, *pattern)
	}
	if cfg.allowAnyOrigin && len(originPatterns) > 0 {
		// discard the errors accumulated in errs and return a single error
		const msg = "specifying origin patterns in addition to * is prohibited"
		return util.NewError(msg)
	}
	cfg.tmp.insecureOriginPatterns = insecureOriginPatterns
	cfg.tmp.publicSuffixes = publicSuffixes
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	if cfg.allowAnyOrigin {
		return nil
	}
	corpus := make(origins.Corpus)
	for _, pattern := range originPatterns {
		corpus.Add(&pattern)
	}
	cfg.corpus = corpus
	return nil
}

func (cfg *config) validateMethods(names []string) error {
	if len(names) == 0 {
		return nil
	}
	sizeHint := len(names) // optimizing for no dupes
	allowedMethods := make(util.Set[string], sizeHint)
	var errs []error
	for _, name := range names {
		if name == headers.ValueWildcard {
			cfg.allowAnyMethod = true
			continue
		}
		if !methods.IsValid(name) {
			err := util.Errorf("invalid method name %q", name)
			errs = append(errs, err)
			continue
		}
		if methods.IsForbidden(name) {
			err := util.Errorf("forbidden method name %q", name)
			errs = append(errs, err)
			continue
		}
		allowedMethods.Add(name)
	}
	if cfg.allowAnyMethod && len(allowedMethods) > 0 {
		// discard the errors accumulated in errs and return a single error
		const msg = "specifying methods in addition to * is prohibited"
		return util.NewError(msg)
	}
	// Because safelisted methods need not be explicitly allowed
	// (see https://stackoverflow.com/a/71429784/2541573),
	// let's remove them silently.
	maps.DeleteFunc(allowedMethods, methods.IsSafelisted)
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	if cfg.allowAnyMethod {
		return nil
	}
	cfg.allowedMethods = allowedMethods
	return nil
}

func (cfg *config) validateRequestHeaders(names []string) error {
	if len(names) == 0 {
		return nil
	}
	allowedHeaders := make([]string, 0, len(names))
	var maxLength int
	var errs []error
	for _, name := range names {
		if name == headers.ValueWildcard {
			cfg.asteriskReqHdrs = true
			continue
		}
		if !headers.IsValid(name) {
			err := util.Errorf("invalid request-header name %q", name)
			errs = append(errs, err)
			continue
		}
		// Fetch-compliant browsers byte-lowercase header names
		// before writing them to the ACRH header; see
		// https://fetch.spec.whatwg.org/#cors-unsafe-request-header-names,
		// step 6.
		normalized := util.ByteLowercase(name)
		if headers.IsForbiddenRequestHeaderName(normalized) {
			err := util.Errorf("forbidden request-header name %q", name)
			errs = append(errs, err)
			continue
		}
		if headers.IsProhibitedRequestHeaderName(normalized) {
			err := util.Errorf("prohibited request-header name %q", name)
			errs = append(errs, err)
			continue
		}
		maxLength = max(maxLength, len(normalized))
		allowedHeaders = append(allowedHeaders, normalized)
		if normalized == headers.Authorization {
			cfg.allowAuthorization = true
		}
	}
	sortedSet := util.NewSortedSet(allowedHeaders...)

	if size := sortedSet.Size(); cfg.asteriskReqHdrs &&
		(size > 1 || !cfg.allowAuthorization && size > 0) {
		// discard the errors accumulated in errs and return a single error
		const msg = "specifying request-header names " +
			"(other than Authorization) in addition to * is prohibited"
		return util.NewError(msg)
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	if cfg.asteriskReqHdrs {
		return nil
	}
	cfg.allowedReqHdrs = sortedSet
	return nil
}

func (cfg *config) validateMaxAge(delta int) error {
	const noPreflightCaching = -1 // sentinel value
	if delta < noPreflightCaching {
		const tmpl = "specified max-age value %d is invalid"
		return util.Errorf(tmpl, delta)
	}
	if delta == noPreflightCaching {
		cfg.acma = []string{"0"}
		return nil
	}
	if delta == 0 { // leave cfg.ACMA at nil
		return nil
	}
	// Current upper bounds:
	//  - Firefox: 86400 (24h)
	//  - Chromium: 7200 (2h)
	//  - WebKit/Safari: 600 (10m)
	// see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age#delta-seconds
	const upperBound = 86400
	if delta > upperBound {
		const tmpl = "specified max-age value %d exceeds upper bound %d"
		return util.Errorf(tmpl, delta, upperBound)
	}
	cfg.acma = []string{strconv.Itoa(delta)}
	return nil
}

func (cfg *config) validateResponseHeaders(names []string) error {
	if len(names) == 0 {
		return nil
	}
	exposedHeaders := make([]string, 0, len(names))
	var errs []error
	for _, name := range names {
		if name == headers.ValueWildcard {
			cfg.exposeAllResHdrs = true
			continue
		}
		if !headers.IsValid(name) {
			err := util.Errorf("invalid response-header name %q", name)
			errs = append(errs, err)
			continue
		}
		normalized := util.ByteLowercase(name)
		if headers.IsForbiddenResponseHeaderName(normalized) {
			err := util.Errorf("forbidden response-header name %q", name)
			errs = append(errs, err)
			continue
		}
		if headers.IsProhibitedResponseHeaderName(normalized) {
			err := util.Errorf("prohibited response-header name %q", name)
			errs = append(errs, err)
			continue
		}
		if headers.IsSafelistedResponseHeaderName(normalized) {
			const tmpl = "response-header name %q needs not be explicitly exposed"
			err := util.Errorf(tmpl, name)
			errs = append(errs, err)
			continue
		}
		exposedHeaders = append(exposedHeaders, normalized)
	}
	slices.Sort(exposedHeaders)
	exposedHeaders = slices.Compact(exposedHeaders)
	if cfg.exposeAllResHdrs && len(exposedHeaders) > 0 {
		// discard the errors accumulated in errs and return a single error
		const msg = "specifying response-header names in addition to * is prohibited"
		return util.NewError(msg)
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	cfg.tmp.exposedResHdrs = exposedHeaders
	return nil
}

func (cfg *config) validatePreflightStatus(status int) error {
	if status == 0 {
		cfg.preflightStatus = http.StatusNoContent
		return nil
	}
	// see https://fetch.spec.whatwg.org/#ok-status
	if !(200 <= status && status < 300) {
		const tmpl = "specified status %d lies outside the 2xx range"
		return util.Errorf(tmpl, status)
	}
	cfg.preflightStatus = status
	return nil
}

func (cfg *config) validate() error {
	var errs []error
	pna := cfg.privateNetworkAccess || cfg.privateNetworkAccessNoCors
	if cfg.allowAnyOrigin {
		if cfg.credentialed {
			const msg = "for security reasons, you cannot both allow all " +
				"origins and enable credentialed access"
			errs = append(errs, util.NewError(msg))
		}
		if pna {
			// see note in
			// https://developer.chrome.com/blog/private-network-access-preflight/#no-cors-mode
			const msg = "for security reasons, you cannot both allow all " +
				"origins and enable Private-Network Access"
			errs = append(errs, util.NewError(msg))
		}
	}
	if len(cfg.tmp.insecureOriginPatterns) > 0 &&
		!cfg.tmp.insecureOrigins &&
		(cfg.credentialed || pna) {
		// We don't require ExtraConfig.DangerouslyTolerateInsecureOrigins to
		// be set when users specify one or more insecure origin patterns in
		// anonymous-only mode and without some form of PNA;
		// in such cases, insecure origins like http://example.com are indeed
		// no less insecure than * is, which itself doesn't require
		// ExtraConfig.DangerouslyTolerateInsecureOrigins to be set.
		var errorMsg strings.Builder
		var patterns = cfg.tmp.insecureOriginPatterns
		errorMsg.WriteString(`for security reasons, insecure origin patterns like `)
		util.Join(&errorMsg, patterns)
		errorMsg.WriteString(` are by default prohibited when `)
		if cfg.credentialed {
			errorMsg.WriteString("credentialed access is enabled")
		}
		if pna {
			if cfg.credentialed {
				errorMsg.WriteString(" and/or ")
			}
			errorMsg.WriteString("Private-Network Access is enabled")
		}
		err := util.NewError(errorMsg.String())
		errs = append(errs, err)
	}
	if len(cfg.tmp.publicSuffixes) > 0 &&
		!cfg.tmp.subsOfPublicSuffixes {
		var errorMsg strings.Builder
		errorMsg.WriteString(`for security reasons, origin patterns like `)
		util.Join(&errorMsg, cfg.tmp.publicSuffixes)
		errorMsg.WriteString(` that encompass subdomains of a public suffix`)
		errorMsg.WriteString(" are by default prohibited")
		err := util.NewError(errorMsg.String())
		errs = append(errs, err)
	}
	if cfg.privateNetworkAccess && cfg.privateNetworkAccessNoCors {
		const msg = "at most one form of Private-Network Access can be enabled"
		errs = append(errs, util.NewError(msg))
	}
	if cfg.exposeAllResHdrs && cfg.credentialed {
		const msg = "you cannot both expose all response headers and enable " +
			"credentialed access"
		errs = append(errs, util.NewError(msg))
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}
