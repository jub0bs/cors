package cors

import (
	"maps"
	"net/http"
	"sync"

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
// which can be toggled by calling their [*Middleware.SetDebug] method.
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
// The debug mode of a passthrough middleware is invariably off.
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
	mu    sync.RWMutex // guards the other fields
	icfg  *internalConfig
	debug bool
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
	var m Middleware
	icfg, err := newInternalConfig(&cfg)
	if err != nil {
		return nil, err
	}
	m.icfg = icfg
	return &m, nil
}

// Reconfigure reconfigures m in accordance with cfg.
// If cfg is nil, it turns m into a passthrough middleware.
// If *cfg is invalid, it leaves m unchanged and returns some non-nil error.
// Otherwise, it successfully reconfigures m, leaves m's debug mode unchanged,
// and returns a nil error.
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
	icfg, err := newInternalConfig(cfg)
	if err != nil {
		return err
	}
	m.mu.Lock()
	{
		m.icfg = icfg
		// If the desired middleware is passthrough, unset m's debug mode;
		// otherwise, leave it unchanged.
		m.debug = cfg != nil && m.debug
	}
	m.mu.Unlock()
	return nil
}

// Wrap applies the CORS middleware to the specified handler.
func (m *Middleware) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var icfg *internalConfig
		var debug bool
		m.mu.RLock()
		{
			icfg = m.icfg
			debug = m.debug
		}
		m.mu.RUnlock()
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
			icfg.handleCORSPreflight(w, r.Header, origin, originSgl, acrm, acrmSgl, debug)
			return
		}
		// r is an "actual" (i.e. non-preflight) CORS request.
		icfg.handleCORSActual(w, origin, originSgl, isOPTIONS)
		h.ServeHTTP(w, r)
	})
}

func (icfg *internalConfig) handleNonCORS(resHdrs http.Header, isOPTIONS bool) {
	if isOPTIONS {
		// see the implementation comment in handleCORSPreflight
		resHdrs.Add(headers.Vary, headers.ValueVaryOptions)
	}
	if icfg.privateNetworkAccessNoCors {
		return
	}
	if !icfg.tree.IsEmpty() {
		// See https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches.
		// Note that we deliberately list "Origin" in the Vary header of responses
		// to actual requests even in cases where a single origin is allowed,
		// because doing so is simpler to implement and unlikely to be
		// detrimental to Web caches.
		if !isOPTIONS {
			resHdrs.Add(headers.Vary, headers.Origin)
		}
		// nothing to do: at this stage, we've already added a Vary header
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
	resHdrs := w.Header()
	// Responses to OPTIONS requests are not meant to be cached
	// (see https://httpwg.org/specs/rfc9110.html#rfc.section.9.3.7)
	// but, for better or worse, some caching intermediaries can nevertheless
	// be configured to cache such responses.
	// To avoid poisoning such caches with inadequate preflight responses,
	// middleware provided by this package by default lists
	// the following header names in the Vary header of preflight responses:
	//
	//   - Access-Control-Request-Headers
	//   - Access-Control-Request-Methods
	//   - Access-Control-Request-Private-Network
	//   - Origin
	vary, found := resHdrs[headers.Vary]
	if !found { // fast path
		resHdrs[headers.Vary] = headers.PreflightVarySgl
	} else { // slow path
		resHdrs[headers.Vary] = append(vary, headers.ValueVaryOptions)
	}

	// Populating a small (8 keys or fewer) local map incurs 0 heap
	// allocations on average; see https://go.dev/play/p/RQdNE-pPCQq.
	// Therefore, using a different data structure for accumulating response
	// headers provides no performance advantage; a simple http.Header will do.
	const bufSizeHint = 5 // enough to hold ACAO, ACAC, ACAPN, ACAM, and ACAH
	buf := make(http.Header, bufSizeHint)

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
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// At this stage, browsers fail the CORS-preflight check
	// (see https://fetch.spec.whatwg.org/#cors-preflight-fetch-0, step 7)
	// if the response status is not an ok status
	// (see https://fetch.spec.whatwg.org/#ok-status).
	if !icfg.processACRPN(buf, reqHdrs) {
		if debug {
			maps.Copy(resHdrs, buf)
			w.WriteHeader(int(icfg.preflightStatusMinus200) + 200)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if !icfg.processACRM(buf, acrm, acrmSgl) {
		if debug {
			maps.Copy(resHdrs, buf)
			w.WriteHeader(int(icfg.preflightStatusMinus200) + 200)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if !icfg.processACRH(buf, reqHdrs, debug) {
		if debug {
			maps.Copy(resHdrs, buf)
			w.WriteHeader(int(icfg.preflightStatusMinus200) + 200)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}
	// Preflight was successful.

	maps.Copy(resHdrs, buf)
	if icfg.acma != nil {
		resHdrs[headers.ACMA] = icfg.acma
	}
	w.WriteHeader(int(icfg.preflightStatusMinus200) + 200)
}

func (icfg *internalConfig) processOriginForPreflight(
	buf http.Header,
	origin string,
	originSgl []string,
) bool {
	o, ok := origins.Parse(origin)
	if !ok {
		return false
	}
	if !icfg.credentialed && icfg.tree.IsEmpty() {
		buf[headers.ACAO] = headers.WildcardSgl
		return true
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

func (icfg *internalConfig) processACRPN(buf, reqHdrs http.Header) bool {
	// See https://wicg.github.io/private-network-access/#cors-preflight.
	//
	// PNA-compliant browsers send at most one ACRPN header;
	// see https://wicg.github.io/private-network-access/#fetching
	// (step 10.2.1.1).
	acrpn, _, found := headers.First(reqHdrs, headers.ACRPN)
	if !found || acrpn != headers.ValueTrue { // no request for PNA
		return true
	}
	if icfg.privateNetworkAccess || icfg.privateNetworkAccessNoCors {
		buf[headers.ACAPN] = headers.TrueSgl
		return true
	}
	return false
}

// Note: only for _non-preflight_ CORS requests
func (icfg *internalConfig) handleCORSActual(
	w http.ResponseWriter,
	origin string,
	originSgl []string,
	isOPTIONS bool,
) {
	resHdrs := w.Header()
	// see https://wicg.github.io/private-network-access/#shortlinks
	if icfg.privateNetworkAccessNoCors {
		if isOPTIONS {
			// see the implementation comment in handleCORSPreflight
			resHdrs.Add(headers.Vary, headers.ValueVaryOptions)
		}
		return
	}
	switch {
	case isOPTIONS:
		// see the implementation comment in handleCORSPreflight
		resHdrs.Add(headers.Vary, headers.ValueVaryOptions)
	case !icfg.tree.IsEmpty():
		// See https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches.
		resHdrs.Add(headers.Vary, headers.Origin)
	}
	if !icfg.credentialed && icfg.tree.IsEmpty() {
		// See the last paragraph in
		// https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches.
		// Note that we deliberately list "Origin" in the Vary header of responses
		// to actual requests even in cases where a single origin is allowed,
		// because doing so is simpler to implement and unlikely to be
		// detrimental to Web caches.
		resHdrs.Set(headers.ACAO, headers.ValueWildcard)
		if icfg.aceh != "" {
			// see https://github.com/whatwg/fetch/issues/1601
			resHdrs.Set(headers.ACEH, icfg.aceh)
		}
		return
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
	// Fetch-compliant browsers send at most one ACRH header;
	// see https://fetch.spec.whatwg.org/#cors-preflight-fetch-0 (step 5).
	// However, some intermediaries may well
	// (and some reportedly do) split it into multiple ACRH field lines;
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
		// We can simply reflect all the ACRH field lines as ACAH field lines
		// because the Fetch standard requires browsers to handle multiple ACAH
		// field lines;
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
		if icfg.allowedReqHdrs.Size() == 0 {
			return false
		}
		if !headers.Check(icfg.allowedReqHdrs, acrh) {
			return false
		}
		// We can simply reflect all the ACRH field lines as ACAH field lines
		// because the Fetch standard requires browsers to handle multiple ACAH
		// field lines;
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
// If m happens to be a passthrough middleware,
// its debug mode is invariably off and SetDebug is a no-op.
func (m *Middleware) SetDebug(b bool) {
	m.mu.Lock()
	{
		m.debug = b
	}
	m.mu.Unlock()
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
	var icfg *internalConfig
	m.mu.RLock()
	{
		icfg = m.icfg
	}
	m.mu.RUnlock()
	return newConfig(icfg)
}
