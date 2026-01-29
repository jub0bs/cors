package cors

import (
	"maps"
	"net/http"
	"sync/atomic"

	"github.com/jub0bs/cors/internal/headers"
	"github.com/jub0bs/cors/internal/methods"
	"github.com/jub0bs/cors/internal/origins"
)

// A Middleware is a CORS middleware.
// Call its [*Middleware.Wrap] method to apply it to a [http.Handler].
//
// The zero value is ready to use but is a mere "passthrough" middleware,
// i.e. a middleware that simply delegates to the handler(s) it wraps.
// To obtain a proper CORS middleware, you should call [NewMiddleware]
// and pass it a valid [Config].
//
// Middleware have a debug mode,
// which can be toggled by calling their [*Middleware.SetDebug] method
// and queried by calling their [*Middleware.Debug] method.
// You should turn debug mode on whenever you're struggling to troubleshoot
// some [CORS-preflight] issue;
// however, be aware that keeping debug mode on may lead to observably poorer
// middleware performance in the face of some adversarial preflight requests.
// When debug mode is off, the information that the middleware includes in
// preflight responses is minimal, for efficiency and confidentiality reasons;
// however, when preflight fails, the browser then lacks enough contextual
// information about the failure to produce a helpful CORS error message.
// In contrast, when debug mode is on and preflight fails,
// the middleware includes enough contextual information about the
// preflight failure in the response for browsers to produce
// a helpful CORS error message.
//
// A Middleware must not be copied after first use.
//
// Middleware are safe for concurrent use by multiple goroutines.
// Therefore, you are free to expose some or all of their methods
// so you can exercise them without having to restart your server;
// however, if you do expose those methods, you should only do so on some
// internal or authorized endpoints, for security reasons.
//
// [CORS-preflight]: https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request
type Middleware struct {
	icfg  atomic.Pointer[internalConfig]
	debug atomic.Bool
}

// NewMiddleware creates a CORS middleware that behaves in accordance with cfg.
// If cfg is invalid, it returns a nil [*Middleware] and some non-nil error.
// Otherwise, it returns a pointer to a CORS [Middleware] and a nil error.
//
// The debug mode of the resulting middleware is off.
//
// Mutating the fields of cfg after NewMiddleware has returned a functioning
// middleware does not alter the latter's behavior.
// However, you can reconfigure a [Middleware] via its
// [*Middleware.Reconfigure] method.
//
// If you need to programmatically handle the configuration errors constitutive
// of the resulting error, rely on package [github.com/jub0bs/cors/cfgerrors].
func NewMiddleware(cfg Config) (*Middleware, error) {
	icfg, err := newInternalConfig(&cfg)
	if err != nil {
		return nil, err
	}
	var m Middleware
	m.icfg.Store(icfg)
	return &m, nil
}

// Reconfigure reconfigures m in accordance with cfg,
// leaving m's debug mode unchanged.
// If cfg is nil, it turns m into a passthrough middleware.
// If *cfg is invalid, it leaves m unchanged and returns some non-nil error.
// Otherwise, it successfully reconfigures m and returns a nil error.
// The following statement is guaranteed to be a no-op
// (albeit a relatively expensive one):
//
//	m.Reconfigure(m.Config())
//
// Note that
//
//	mw := new(cors.Middleware)
//	err := mw.Reconfigure(&cfg)
//
// is functionally equivalent to
//
//	mw, err := cors.NewMiddleware(cfg)
//
// You can safely reconfigure a middleware
// even as it's concurrently processing requests.
//
// Mutating the fields of cfg after Reconfigure has returned does not alter
// m's behavior.
//
// If you need to programmatically handle the configuration errors constitutive
// of the resulting error, rely on package [github.com/jub0bs/cors/cfgerrors].
func (m *Middleware) Reconfigure(cfg *Config) error {
	// Rather than attempt to diff the new config against the current one,
	// we simply start from scratch; for common configurations, doing so indeed
	// is performant enough.
	icfg, err := newInternalConfig(cfg)
	if err != nil {
		return err
	}
	m.icfg.Store(icfg)
	return nil
}

// Wrap applies the CORS middleware to the specified handler.
func (m *Middleware) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		icfg := m.icfg.Load()
		if icfg == nil { // passthrough middleware
			h.ServeHTTP(w, r)
			return
		}
		isOPTIONS := r.Method == http.MethodOptions
		// Fetch-compliant browsers send at most one Origin header;
		// see https://fetch.spec.whatwg.org/#http-network-or-cache-fetch
		// (step 12).
		origin, originSgl, found := headers.First(r.Header, headers.Origin)
		if !found {
			// r is NOT a CORS request;
			// see https://fetch.spec.whatwg.org/#cors-request.
			icfg.handleNonCORS(w.Header(), isOPTIONS)
			h.ServeHTTP(w, r)
			return
		}
		// r is a CORS request (and possibly a CORS-preflight request);
		// see https://fetch.spec.whatwg.org/#cors-request.

		// Fetch-compliant browsers send at most one ACRM header;
		// see https://fetch.spec.whatwg.org/#cors-preflight-fetch (step 3).
		acrm, acrmSgl, found := headers.First(r.Header, headers.ACRM)
		if isOPTIONS && found {
			// r is a CORS-preflight request;
			// see https://fetch.spec.whatwg.org/#cors-preflight-request.
			debug := m.debug.Load()
			// Note that, because h.ServeHTTP is not called in this branch,
			// we can safely rely, for performance, on some precomputed slices
			// for adding/setting headers.
			icfg.handleCORSPreflight(w, r.Header, origin, originSgl, acrm, acrmSgl, debug)
			return
		}
		// r is an "actual" (i.e. non-preflight) CORS request.
		icfg.handleCORSActual(w.Header(), origin, originSgl, isOPTIONS)
		h.ServeHTTP(w, r)
	})
}

func (icfg *internalConfig) handleNonCORS(resHdrs http.Header, isOPTIONS bool) {
	// It's tempting to rely (for performance) on some precomputed slices for
	// the response headers we add/set here, as we do in handleCORSPreflight.
	// However, doing so here is fraught with peril, because it would provide
	// the wrapped handler an undesirable affordance: mutation of those slices.
	// See https://github.com/rs/cors/issues/198.

	if !icfg.tree.IsEmpty() {
		if !isOPTIONS {
			// See https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches.
			// Note that we deliberately list "Origin" in the Vary header of
			// responses to actual requests even in cases where a single origin
			// is allowed, because doing so is simpler to implement and
			// unlikely to be detrimental to Web caches. See also
			// https://github.com/whatwg/fetch/issues/1601#issuecomment-1418899997.
			//
			// Note that we must add rather than set a Vary header here,
			// because outer middleware may have already added/set a Vary
			// header, which we wouldn't want to clobber.
			resHdrs.Add(headers.Vary, headers.Origin)
		}
		return
	}

	resHdrs.Set(headers.ACAO, headers.ValueWildcard)
	if icfg.aceh != "" {
		// see https://github.com/whatwg/fetch/issues/1601
		resHdrs.Set(headers.ACEH, icfg.aceh)
	}
}

func (icfg *internalConfig) handleCORSPreflight(
	w http.ResponseWriter,
	reqHdrs http.Header,
	origin string,
	originSgl []string,
	acrm string,
	acrmSgl []string,
	debug bool,
) {
	// Some notes about Vary in the context of CORS preflight:
	//  - Contrary to popular belief, the presence of a Vary header in
	//    responses to preflight requests has no bearing on the behavior of
	//    browsers' CORS-preflight cache;
	//    see https://fetch.spec.whatwg.org/#concept-cache and
	//    https://stackoverflow.com/a/42849375/2541573.
	//  - Even though some caching intermediaries can be configured to cache
	//    responses to OPTIONS requests, such caching contravenes RFC 9110;
	//    see https://httpwg.org/specs/rfc9110.html#rfc.section.9.3.7.
	//    Some CORS middleware libraries (such as github.com/rs/cors) do cater
	//    for such non-compliant behavior; let's not.

	if !icfg.preflight && !debug {
		w.WriteHeader(preflightFailStatus)
		return
	}

	// Populating a small (8 keys or fewer) local map incurs 0 heap
	// allocations on average; see https://go.dev/play/p/RQdNE-pPCQq.
	// Therefore, using a different data structure for accumulating response
	// headers provides no performance advantage; a simple http.Header will do.
	buf := make(http.Header)

	resHdrs := w.Header()

	// When debug is on and a preflight step fails,
	// we omit the remaining CORS response headers
	// and let the browser fail the CORS-preflight fetch;
	// however, for easier troubleshooting on the client side,
	// we do respond with an ok status.
	//
	// When debug is off and preflight fails,
	// we omit all CORS headers from the preflight response.

	// For details about the order in which we perform the following checks,
	// see https://fetch.spec.whatwg.org/#cors-preflight-fetch, item 7.
	if !icfg.processOriginForPreflight(buf, origin, originSgl) {
		if debug {
			maps.Copy(resHdrs, buf)
		}
		w.WriteHeader(preflightFailStatus)
		return
	}

	// At this stage, browsers fail the CORS-preflight check
	// (see https://fetch.spec.whatwg.org/#cors-preflight-fetch-0, step 7)
	// if the response status is not an ok status
	// (see https://fetch.spec.whatwg.org/#ok-status).

	if !icfg.processACRM(buf, acrm, acrmSgl) {
		if debug {
			maps.Copy(resHdrs, buf)
			w.WriteHeader(preflightOKStatus)
			return
		}
		w.WriteHeader(preflightFailStatus)
		return
	}

	if !icfg.processACRH(buf, reqHdrs, debug) {
		if debug {
			maps.Copy(resHdrs, buf)
			w.WriteHeader(preflightOKStatus)
			return
		}
		w.WriteHeader(preflightFailStatus)
		return
	}
	// Preflight was successful.

	maps.Copy(resHdrs, buf)
	if icfg.acma != nil {
		resHdrs[headers.ACMA] = icfg.acma
	}
	w.WriteHeader(preflightOKStatus)
}

func (icfg *internalConfig) processOriginForPreflight(
	buf http.Header,
	origin string,
	originSgl []string,
) bool {
	if icfg.tree.IsEmpty() {
		buf[headers.ACAO] = headers.WildcardSgl
		return true
	}
	o, ok := origins.Parse(origin)
	if !ok {
		return false
	}
	if !icfg.tree.Contains(&o) {
		return false
	}
	buf[headers.ACAO] = originSgl
	if icfg.credentialed {
		// We make no attempt to infer whether the request is credentialed,
		// simply because preflight requests don't carry credentials;
		// see https://fetch.spec.whatwg.org/#example-xhr-credentials.
		buf[headers.ACAC] = headers.TrueSgl
	}
	return true
}

// Note: only for _non-preflight_ CORS requests
func (icfg *internalConfig) handleCORSActual(
	resHdrs http.Header,
	origin string,
	originSgl []string,
	isOPTIONS bool,
) {
	// It's tempting to rely (for performance) on some precomputed slices for
	// the response headers we add/set here, as we do in handleCORSPreflight.
	// However, doing so here is fraught with peril, because it would provide
	// the wrapped handler an undesirable affordance: mutation of those slices.
	// See https://github.com/rs/cors/issues/198.

	if icfg.tree.IsEmpty() {
		// See https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches.
		resHdrs.Set(headers.ACAO, headers.ValueWildcard)
	} else {
		if !isOPTIONS {
			// See https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches.
			// Note that we deliberately list "Origin" in the Vary header of
			// responses to actual requests even in cases where a single origin
			// is allowed, because doing so is simpler to implement and
			// unlikely to be detrimental to Web caches. See also
			// https://github.com/whatwg/fetch/issues/1601#issuecomment-1418899997.
			//
			// Note that we must add rather than set a Vary header here,
			// because outer middleware may have already added/set a Vary
			// header, which we wouldn't want to clobber.
			resHdrs.Add(headers.Vary, headers.Origin)
		}
		o, ok := origins.Parse(origin)
		if !ok || !icfg.tree.Contains(&o) {
			return
		}
		resHdrs[headers.ACAO] = originSgl
		if icfg.credentialed {
			// We make no attempt to infer whether the request is credentialed;
			// in fact, a request’s credentials mode is not necessarily observable
			// on the server.
			// Instead, we systematically include "ACAC: true" if credentialed
			// access is enabled and request's origin is allowed.
			// See https://fetch.spec.whatwg.org/#example-xhr-credentials.
			resHdrs.Set(headers.ACAC, headers.ValueTrue)
		}
	}

	if icfg.aceh != "" {
		resHdrs.Set(headers.ACEH, icfg.aceh)
	}
}

func (icfg *internalConfig) processACRM(
	buf http.Header,
	acrm string,
	acrmSgl []string,
) bool {
	if methods.IsSafelisted(acrm) {
		// CORS-safelisted methods get a free pass; see
		// https://fetch.spec.whatwg.org/#ref-for-cors-safelisted-method%E2%91%A2.
		// Therefore, no need to set the ACAM header in this case.
		return true
	}
	// Note that middleware only ever list a single method in the ACAM header.
	// One inconvenient of this behavior is that it leads to less than ideal
	// caching by the browser of responses to CORS-preflight requests;
	// see https://fetch.spec.whatwg.org/#cors-preflight-cache.
	// However, this behavior presents two advantages with respect to responses
	// to CORS-preflight requests:
	//   - those responses disclose no other allowed methods than the one
	//     required for preflight to succeed; and
	//   - those responses are smaller than they would otherwise be,
	//     thereby saving some bandwidth.
	if icfg.allowAnyMethod && !icfg.credentialed {
		buf[headers.ACAM] = headers.WildcardSgl
		return true
	}
	if icfg.allowAnyMethod || icfg.allowedMethods.Contains(acrm) {
		buf[headers.ACAM] = acrmSgl
		return true
	}
	return false
}

func (icfg *internalConfig) processACRH(
	buf http.Header,
	reqHdrs http.Header,
	debug bool,
) bool {
	// Fetch-compliant browsers send at most one ACRH header line;
	// see https://fetch.spec.whatwg.org/#cors-preflight-fetch-0 (step 5).
	// However, some intermediaries may well
	// (and some reportedly do) split it into multiple ACRH header lines;
	// see https://github.com/rs/cors/issues/184.
	acrh, found := reqHdrs[headers.ACRH]
	if !found {
		return true
	}
	if icfg.asteriskReqHdrs && !icfg.credentialed {
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
			buf[headers.ACAH] = headers.WildcardAuthSgl
		} else {
			buf[headers.ACAH] = headers.WildcardSgl
		}
		return true
	}
	if icfg.asteriskReqHdrs && icfg.credentialed {
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
		//
		// We can simply reflect all the ACRH header lines as ACAH header lines
		// because the Fetch standard requires browsers to handle multiple ACAH
		// header lines;
		// see https://fetch.spec.whatwg.org/#cors-preflight-fetch-0.
		//
		// Reflecting ACRH into ACAH isn't ideal for performance in cases where
		// ACRH is full of junk, but there isn't much else we can do, other than
		// discourage users from both enabling credentialed access and allowing
		// all request-header names.
		buf[headers.ACAH] = acrh
		return true
	}
	if !debug {
		if !headers.Check(icfg.allowedReqHdrs, acrh) {
			return false
		}
		// We can simply reflect all the ACRH header lines as ACAH header lines
		// because the Fetch standard requires browsers to handle multiple ACAH
		// header lines;
		// see https://fetch.spec.whatwg.org/#cors-preflight-fetch-0.
		//
		// Reflecting ACRH into ACAH isn't ideal for performance in cases where
		// ACRH is full of junk, but there isn't much else we can do, other than
		// discourage users from keeping debug mode on for extended periods of
		// time.
		buf[headers.ACAH] = acrh
		return true
	}
	if icfg.acah != nil {
		buf[headers.ACAH] = icfg.acah
		return true
	}
	return false
}

// SetDebug turns debug mode on (if b is true) or off (otherwise).
func (m *Middleware) SetDebug(b bool) {
	m.debug.Store(b)
}

// Debug reports whether m's debug mode is on.
func (m *Middleware) Debug() bool {
	return m.debug.Load()
}

// Config returns a pointer to a deep copy of m's current configuration;
// if m is a passthrough middleware, it simply returns nil.
// The result may differ from the [Config] with which m was created or last
// reconfigured, but the following statement is guaranteed to be a no-op
// (albeit a relatively expensive one):
//
//	m.Reconfigure(m.Config())
//
// Mutating the fields of the result does not alter m's behavior.
// However, you can reconfigure a [Middleware] via its
// [*Middleware.Reconfigure] method.
func (m *Middleware) Config() *Config {
	return newConfig(m.icfg.Load())
}
