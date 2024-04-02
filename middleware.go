package cors

import (
	"net/http"
	"sync/atomic"

	"github.com/jub0bs/cors/internal/headers"
	"github.com/jub0bs/cors/internal/methods"
	"github.com/jub0bs/cors/internal/origins"
)

// A Middleware is a CORS middleware.
// It is safe for concurrent use by multiple goroutines.
type Middleware struct {
	debugMode *atomic.Bool
	f         func(h http.Handler) http.Handler
}

// Wrap applies the CORS middleware to the specified handler.
func (m *Middleware) Wrap(h http.Handler) http.Handler {
	return m.f(h)
}

// SetDebug turns debug mode on (if b is true) or off (otherwise),
// its default state.
//
// You should activate debug mode when you're struggling to troubleshoot
// some CORS issue.
//
// When debug mode is off, the information that the middleware includes in
// preflight responses is minimal, for efficiency and confidentiality reasons.
// However, if preflight fails, the browser lacks enough contextual information
// about the failure to produce a helpful CORS error message.
// As a result, troubleshooting CORS issues can prove [difficult].
//
// In contrast, when debug mode is on and preflight fails,
// the middleware includes just enough contextual information about the
// preflight failure in the response for browsers to produce
// a helpful CORS error message.
// Therefore, debug mode eases troubleshooting of CORS issues.
//
// Note that, because this method is concurrency-safe
// (it can be safely called even when the middleware is processing requests),
// calling it doesn't require a server restart;
// you may even want to expose it on some internal or authenticated endpoint,
// so that you can toggle debug mode in production.
//
// [difficult]: https://jub0bs.com/posts/2023-02-08-fearless-cors/#9-ease-troubleshooting-by-eschewing-shortcuts-during-preflight
func (m *Middleware) SetDebug(b bool) {
	m.debugMode.Store(b)
}

// NewMiddleware creates a CORS middleware that behaves in accordance with
// the specified configuration. If its [Config] argument is invalid,
// this function returns a nil [*Middleware] and some non-nil error.
// Otherwise, it returns a pointer to a functioning [Middleware]
// and a nil error.
//
// The resulting CORS middleware is immutable;
// more specifically, mutating the fields of a [Config] value that was used to
// create a Middleware does not alter the latter's configuration or behavior.
func NewMiddleware(c Config) (*Middleware, error) {
	cfg, err := newConfig(&c)
	if err != nil {
		return nil, err
	}
	middlewareFunc := func(h http.Handler) http.Handler {
		f := func(w http.ResponseWriter, r *http.Request) {
			options := r.Method == http.MethodOptions
			// Fetch-compliant browsers send at most one Origin header;
			// see https://fetch.spec.whatwg.org/#http-network-or-cache-fetch
			// (step 12).
			orig, originSgl, found := headers.First(r.Header, headers.Origin)
			if !found {
				// r is _not_ a CORS request.
				cfg.handleNonCORS(w.Header(), options)
				h.ServeHTTP(w, r)
				return
			}
			// r is a CORS request (and possibly a CORS-preflight request);
			// see https://fetch.spec.whatwg.org/#cors-request.
			if !options {
				// r is a non-OPTIONS CORS request.
				cfg.handleNonPreflightCORS(w, orig, originSgl, options)
				h.ServeHTTP(w, r)
				return
			}
			// Fetch-compliant browsers send at most one ACRM header;
			// see https://fetch.spec.whatwg.org/#cors-preflight-fetch (step 3).
			acrm, acrmSgl, found := headers.First(r.Header, headers.ACRM)
			if found {
				// r is a CORS-preflight request;
				// see https://fetch.spec.whatwg.org/#cors-preflight-request.
				cfg.handleCORSPreflight(w, r.Header, orig, originSgl, acrm, acrmSgl)
				return
			}
			// r is a non-preflight OPTIONS CORS request.
			cfg.handleNonPreflightCORS(w, orig, originSgl, options)
			h.ServeHTTP(w, r)
		}
		return http.HandlerFunc(f)
	}
	m := Middleware{
		debugMode: &cfg.debug,
		f:         middlewareFunc,
	}
	return &m, nil
}

func (cfg *config) handleNonCORS(resHdrs http.Header, options bool) {
	if options {
		// see the implementation comment in handleCORSPreflight
		headers.FastAdd(resHdrs, headers.Vary, headers.ValueVaryOptions, headers.PreflightVarySgl)
	}
	if cfg.privateNetworkAccessNoCors {
		return
	}
	if !cfg.allowAnyOrigin {
		// See https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches.
		// Note that we deliberately list "Origin" in the Vary header of responses
		// to actual requests even in cases where a single origin is allowed,
		// because doing so is simpler to implement and unlikely to be
		// detrimental to Web caches.
		if !options {
			headers.FastAdd(resHdrs, headers.Vary, headers.Origin, headers.OriginSgl)
		}
		// nothing to do: at this stage, we've already added a Vary header
		return
	}
	resHdrs[headers.ACAO] = headers.WildcardSgl
	if cfg.aceh != nil {
		// see https://github.com/whatwg/fetch/issues/1601
		resHdrs[headers.ACEH] = cfg.aceh
	}
}

func (cfg *config) handleCORSPreflight(
	w http.ResponseWriter,
	reqHdrs http.Header,
	orig string,
	originSgl []string,
	acrm string,
	acrmSgl []string,
) {
	resHdrs := w.Header()
	// Responses to OPTIONS requests are not meant to be cached but,
	// for better or worse, some caching intermediaries can nevertheless be
	// configured to cache such responses.
	// To avoid poisoning such caches with inadequate preflight responses,
	// middleware provided by this package by default lists
	// the following header names in the Vary header of preflight responses:
	//
	//   - Access-Control-Request-Headers
	//   - Access-Control-Request-Methods
	//   - Access-Control-Request-Private-Network
	//   - Origin
	headers.FastAdd(resHdrs, headers.Vary, headers.ValueVaryOptions, headers.PreflightVarySgl)

	// For details about the order in which we perform the following checks,
	// see https://fetch.spec.whatwg.org/#cors-preflight-fetch, item 7.
	if !cfg.processOriginForPreflight(resHdrs, orig, originSgl) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// At this stage, browsers fail the CORS-preflight check
	// (see https://fetch.spec.whatwg.org/#cors-preflight-fetch-0, step 7)
	// if the response status is not an ok status
	// (see https://fetch.spec.whatwg.org/#ok-status).
	//
	// When debug is on and a preflight step fails,
	// we omit the remaining CORS response headers
	// and let the browser fail the CORS-preflight fetch,
	// however, for easier troubleshooting on the client side,
	// we do respond with an ok status.
	//
	// When debug is off and preflight fails,
	// we omit all CORS headers from the preflight response.

	debug := cfg.debug.Load() // debug mode adopted for this preflight
	if !cfg.processACRPN(resHdrs, reqHdrs) {
		if debug {
			w.WriteHeader(cfg.preflightStatus)
			return
		}
		delete(resHdrs, headers.ACAO)
		delete(resHdrs, headers.ACAC)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !cfg.processACRM(resHdrs, acrm, acrmSgl) {
		if debug {
			w.WriteHeader(cfg.preflightStatus)
			return
		}
		delete(resHdrs, headers.ACAO)
		delete(resHdrs, headers.ACAC)
		delete(resHdrs, headers.ACAPN)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !cfg.processACRH(resHdrs, reqHdrs, debug) {
		if debug {
			w.WriteHeader(cfg.preflightStatus)
			return
		}
		delete(resHdrs, headers.ACAO)
		delete(resHdrs, headers.ACAC)
		delete(resHdrs, headers.ACAPN)
		delete(resHdrs, headers.ACAM)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if cfg.acma != nil {
		resHdrs[headers.ACMA] = cfg.acma
	}
	w.WriteHeader(cfg.preflightStatus)
}

func (cfg *config) processOriginForPreflight(
	resHdrs http.Header,
	orig string,
	originSgl []string,
) bool {
	o, ok := origins.Parse(orig)
	if !ok {
		return false
	}
	if !cfg.credentialed && cfg.allowAnyOrigin {
		resHdrs[headers.ACAO] = headers.WildcardSgl
		return true
	}
	if !cfg.corpus.Contains(&o) {
		return false
	}
	resHdrs[headers.ACAO] = originSgl
	if cfg.credentialed {
		// We make no attempt to infer whether the request is credentialed,
		// simply because preflight requests don't carry credentials;
		// see https://fetch.spec.whatwg.org/#example-xhr-credentials.
		resHdrs[headers.ACAC] = headers.TrueSgl
	}
	return true
}

func (cfg *config) processACRPN(resHdrs, reqHdrs http.Header) bool {
	// See https://wicg.github.io/private-network-access/#cors-preflight.
	//
	// PNA-compliant browsers send at most one ACRPN header;
	// see https://wicg.github.io/private-network-access/#fetching
	// (step 10.2.1.1).
	acrpn, _, found := headers.First(reqHdrs, headers.ACRPN)
	if !found || acrpn != headers.ValueTrue { // no request for PNA
		return true
	}
	if cfg.privateNetworkAccess || cfg.privateNetworkAccessNoCors {
		resHdrs[headers.ACAPN] = headers.TrueSgl
		return true
	}
	return false
}

// Note: only for _non-preflight_ CORS requests
func (cfg *config) handleNonPreflightCORS(
	w http.ResponseWriter,
	orig string,
	originSgl []string,
	options bool,
) {
	resHdrs := w.Header()
	// see https://wicg.github.io/private-network-access/#shortlinks
	if cfg.privateNetworkAccessNoCors {
		if options {
			// see the implementation comment in handleCORSPreflight
			headers.FastAdd(resHdrs, headers.Vary, headers.ValueVaryOptions, headers.PreflightVarySgl)
		}
		return
	}
	switch {
	case options:
		// see the implementation comment in handleCORSPreflight
		headers.FastAdd(resHdrs, headers.Vary, headers.ValueVaryOptions, headers.PreflightVarySgl)
	case !cfg.allowAnyOrigin:
		// See https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches.
		headers.FastAdd(resHdrs, headers.Vary, headers.Origin, headers.OriginSgl)
	}
	if !cfg.credentialed && cfg.allowAnyOrigin {
		// See the last paragraph in
		// https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches.
		// Note that we deliberately list "Origin" in the Vary header of responses
		// to actual requests even in cases where a single origin is allowed,
		// because doing so is simpler to implement and unlikely to be
		// detrimental to Web caches.
		resHdrs[headers.ACAO] = headers.WildcardSgl
		if cfg.aceh != nil {
			// see https://github.com/whatwg/fetch/issues/1601
			resHdrs[headers.ACEH] = cfg.aceh
		}
		return
	}
	o, ok := origins.Parse(orig)
	if !ok || !cfg.corpus.Contains(&o) {
		return
	}
	resHdrs[headers.ACAO] = originSgl
	if cfg.credentialed {
		// We make no attempt to infer whether the request is credentialed;
		// in fact, a request’s credentials mode is not necessarily observable
		// on the server.
		// Instead, we systematically include "ACAC: true" if credentialed
		// access is enabled and request's origin is allowed.
		// See https://fetch.spec.whatwg.org/#example-xhr-credentials.
		resHdrs[headers.ACAC] = headers.TrueSgl
	}
	if cfg.aceh != nil {
		resHdrs[headers.ACEH] = cfg.aceh
	}
}

func (cfg *config) processACRM(
	hdrs http.Header,
	acrm string,
	acrmSgl []string,
) bool {
	if methods.IsSafelisted(acrm, struct{}{}) {
		// CORS-safelisted methods get a free pass; see
		// https://fetch.spec.whatwg.org/#ref-for-cors-safelisted-method%E2%91%A2.
		// Therefore, no need to set the ACAM header in this case.
		return true
	}
	if cfg.allowAnyMethod && !cfg.credentialed {
		hdrs[headers.ACAM] = headers.WildcardSgl
		return true
	}
	if cfg.allowAnyMethod || cfg.allowedMethods.Contains(acrm) {
		hdrs[headers.ACAM] = acrmSgl
		return true
	}
	return false
}

func (cfg *config) processACRH(resHdrs, reqHdrs http.Header, debug bool) bool {
	// Fetch-compliant browsers send at most one ACRH header;
	// see https://fetch.spec.whatwg.org/#cors-preflight-fetch-0 (step 5).
	acrh, acrhSgl, found := headers.First(reqHdrs, headers.ACRH)
	if !found {
		return true
	}
	if cfg.asteriskReqHdrs && !cfg.credentialed {
		if cfg.allowAuthorization {
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
			// and with "*"" when ACRH does not contain "authorization".
			// However, such an approach would require us to scan the entire
			// ACRH header in search of "authorization",
			// which, in the event of a long ACRH header, would be costly
			// in CPU cycles.
			// Adversaries aware of this subtlety could spoof preflight requests
			// containing a maliciously long ACRH header in order to exercise
			// this costly execution path and thereby generate undue load
			// on the server.
			resHdrs[headers.ACAH] = headers.WildcardAuthSgl
		} else {
			resHdrs[headers.ACAH] = headers.WildcardSgl
		}
		return true
	}
	if cfg.asteriskReqHdrs && cfg.credentialed {
		// If credentialed access is enabled,
		// the single-asterisk pattern denotes all request-header names,
		// including Authorization.
		// Therefore, users of jub0bs/cors cannot both
		// allow all request-header names other than Authorization
		// and allow credentialed access.
		// This limitation is the result of a deliberate design choice.
		//
		// First, rare are the cases where all request-header names
		// other than Authorization should be allowed
		// with credentialed access enabled.
		//
		// Second, because jub0bs/cors prohibits its users from
		// allowing all origins with credentialed access,
		// allowing all request headers from select origins along
		// with credentialed access presents little security-related risks.
		//
		// Third, if we followed an alternative approach
		// in which * doesn't cover Authorization,
		// we would need to scan the ACRH header in search of "authorization";
		// as explained in an implementation comment above,
		// such a computation would introduce performance issues.
		// Moreover, if "authorization" were found in ACRH,
		// we couldn't simply echo ACRH in ACAH,
		// because we'd have to omit "authorization" in ACAH.
		// Incidentally, this could be achieved
		// without incurring heap allocations,
		// e.g. by cutting ACRH around "authorization" and
		// echoing the results in up to two ACAH header(s);
		// but the whole alternative approach is not worth the trouble anyway.
		resHdrs[headers.ACAH] = acrhSgl
		return true
	}
	if !debug {
		if cfg.allowedReqHdrs.Size() == 0 {
			return false
		}
		if !cfg.allowedReqHdrs.Subsumes(acrh) {
			return false
		}
		resHdrs[headers.ACAH] = acrhSgl
		return true
	}
	if cfg.acah != nil {
		resHdrs[headers.ACAH] = cfg.acah
		return true
	}
	return false
}
