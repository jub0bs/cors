package cors

import (
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
// some [CORS-preflight] issue.
// When debug mode is off, the information that the middleware includes in
// preflight responses is minimal, for efficiency and confidentiality reasons;
// however, when preflight fails, the browser then lacks enough contextual
// information about the failure to produce a helpful CORS error message.
// In contrast, when debug mode is on and preflight fails,
// the middleware includes just enough contextual information about the
// preflight failure in the response for browsers to produce
// a helpful CORS error message.
// The debug mode of a passthrough middleware is invariably off.
//
// Middleware are safe for concurrent use by multiple goroutines.
// Therefore, you are free to expose some or all of their methods
// so you can call them without having to restart your server;
// however, if you do expose those methods, you should only do so on some
// internal or authorized endpoints, for security reasons.
//
// [CORS-preflight]: https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request
type Middleware struct {
	icfg *internalConfig
	mu   sync.RWMutex
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
func (m *Middleware) Reconfigure(cfg *Config) error {
	icfg, err := newInternalConfig(cfg)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if icfg != nil && m.icfg != nil {
		// Retain the current debug mode;
		// as a result, m.Reconfigure(m.Config()) is a no-op
		// (albeit an expensive one), which is a nice property.
		icfg.debug = m.icfg.debug
	}
	m.icfg = icfg
	m.mu.Unlock()
	return nil
}

// Wrap applies the CORS middleware to the specified handler.
func (m *Middleware) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.RLock()
		icfg := m.icfg
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
			icfg.handleCORSPreflight(w, r.Header, origin, originSgl, acrm, acrmSgl)
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
	if !icfg.allowAnyOrigin {
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
	vary, found := resHdrs[headers.Vary]
	if !found { // fast path
		resHdrs[headers.Vary] = headers.PreflightVarySgl
	} else { // slow path
		resHdrs[headers.Vary] = append(vary, headers.ValueVaryOptions)
	}

	// Accumulating the response headers in an array rather than in a
	// temporary map allows us to save a few heap allocations.
	var pairs [5]headerPair // enough to hold ACAO, ACAC, ACAPN, ACAM, and ACAH
	buf := pairs[:0]

	// When debug is on and a preflight step fails,
	// we omit the remaining CORS response headers
	// and let the browser fail the CORS-preflight fetch,
	// however, for easier troubleshooting on the client side,
	// we do respond with an ok status.
	//
	// When debug is off and preflight fails,
	// we omit all CORS headers from the preflight response.
	debug := icfg.debug

	// For details about the order in which we perform the following checks,
	// see https://fetch.spec.whatwg.org/#cors-preflight-fetch, item 7.
	buf, ok := icfg.processOriginForPreflight(buf, origin, originSgl)
	if !ok {
		if debug {
			flush(w.Header(), buf)
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// At this stage, browsers fail the CORS-preflight check
	// (see https://fetch.spec.whatwg.org/#cors-preflight-fetch-0, step 7)
	// if the response status is not an ok status
	// (see https://fetch.spec.whatwg.org/#ok-status).
	buf, ok = icfg.processACRPN(buf, reqHdrs)
	if !ok {
		if debug {
			flush(w.Header(), buf)
			w.WriteHeader(icfg.preflightStatus)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}

	buf, ok = icfg.processACRM(buf, acrm, acrmSgl)
	if !ok {
		if debug {
			flush(w.Header(), buf)
			w.WriteHeader(icfg.preflightStatus)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}

	buf, ok = icfg.processACRH(buf, reqHdrs, debug)
	if !ok {
		if debug {
			flush(w.Header(), buf)
			w.WriteHeader(icfg.preflightStatus)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}
	// Preflight was successful.

	flush(w.Header(), buf)
	if icfg.acma != nil {
		resHdrs[headers.ACMA] = icfg.acma
	}
	w.WriteHeader(icfg.preflightStatus)
}

type headerPair struct {
	k string // assumed in canonical format
	v []string
}

func flush(hdrs http.Header, pairs []headerPair) {
	for _, pair := range pairs {
		hdrs[pair.k] = pair.v
	}
}

func (icfg *internalConfig) processOriginForPreflight(
	buf []headerPair,
	origin string,
	originSgl []string,
) ([]headerPair, bool) {
	o, ok := origins.Parse(origin)
	if !ok {
		return buf, false
	}
	if !icfg.credentialed && icfg.allowAnyOrigin {
		pair := headerPair{
			k: headers.ACAO,
			v: headers.WildcardSgl,
		}
		buf = append(buf, pair)
		return buf, true
	}
	if !icfg.corpus.Contains(&o) {
		return buf, false
	}
	pair := headerPair{
		k: headers.ACAO,
		v: originSgl,
	}
	buf = append(buf, pair)
	if icfg.credentialed {
		// We make no attempt to infer whether the request is credentialed,
		// simply because preflight requests don't carry credentials;
		// see https://fetch.spec.whatwg.org/#example-xhr-credentials.
		pair := headerPair{
			k: headers.ACAC,
			v: headers.TrueSgl,
		}
		buf = append(buf, pair)
	}
	return buf, true
}

func (icfg *internalConfig) processACRPN(buf []headerPair, reqHdrs http.Header) ([]headerPair, bool) {
	// See https://wicg.github.io/private-network-access/#cors-preflight.
	//
	// PNA-compliant browsers send at most one ACRPN header;
	// see https://wicg.github.io/private-network-access/#fetching
	// (step 10.2.1.1).
	acrpn, _, found := headers.First(reqHdrs, headers.ACRPN)
	if !found || acrpn != headers.ValueTrue { // no request for PNA
		return buf, true
	}
	if icfg.privateNetworkAccess || icfg.privateNetworkAccessNoCors {
		pair := headerPair{
			k: headers.ACAPN,
			v: headers.TrueSgl,
		}
		buf = append(buf, pair)
		return buf, true
	}
	return buf, false
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
	case !icfg.allowAnyOrigin:
		// See https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches.
		resHdrs.Add(headers.Vary, headers.Origin)
	}
	if !icfg.credentialed && icfg.allowAnyOrigin {
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
	if !ok || !icfg.corpus.Contains(&o) {
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
	buf []headerPair,
	acrm string,
	acrmSgl []string,
) ([]headerPair, bool) {
	if methods.IsSafelisted(acrm, struct{}{}) {
		// CORS-safelisted methods get a free pass; see
		// https://fetch.spec.whatwg.org/#ref-for-cors-safelisted-method%E2%91%A2.
		// Therefore, no need to set the ACAM header in this case.
		return buf, true
	}
	if icfg.allowAnyMethod && !icfg.credentialed {
		pair := headerPair{
			k: headers.ACAM,
			v: headers.WildcardSgl,
		}
		buf = append(buf, pair)
		return buf, true
	}
	if icfg.allowAnyMethod || icfg.allowedMethods.Contains(acrm) {
		pair := headerPair{
			k: headers.ACAM,
			v: acrmSgl,
		}
		buf = append(buf, pair)
		return buf, true
	}
	return buf, false
}

func (icfg *internalConfig) processACRH(
	buf []headerPair,
	reqHdrs http.Header,
	debug bool,
) ([]headerPair, bool) {
	// Fetch-compliant browsers send at most one ACRH header;
	// see https://fetch.spec.whatwg.org/#cors-preflight-fetch-0 (step 5).
	acrh, acrhSgl, found := headers.First(reqHdrs, headers.ACRH)
	if !found {
		return buf, true
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
			pair := headerPair{
				k: headers.ACAH,
				v: headers.WildcardAuthSgl,
			}
			buf = append(buf, pair)
		} else {
			pair := headerPair{
				k: headers.ACAH,
				v: headers.WildcardSgl,
			}
			buf = append(buf, pair)
		}
		return buf, true
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
		pair := headerPair{
			k: headers.ACAH,
			v: acrhSgl,
		}
		buf = append(buf, pair)
		return buf, true
	}
	if !debug {
		if icfg.allowedReqHdrs.Size() == 0 {
			return buf, false
		}
		if !icfg.allowedReqHdrs.Subsumes(acrh) {
			return buf, false
		}
		pair := headerPair{
			k: headers.ACAH,
			v: acrhSgl,
		}
		buf = append(buf, pair)
		return buf, true
	}
	if icfg.acah != nil {
		pair := headerPair{
			k: headers.ACAH,
			v: icfg.acah,
		}
		buf = append(buf, pair)
		return buf, true
	}
	return buf, false
}

// SetDebug turns debug mode on (if b is true) or off (otherwise).
// If m happens to be a passthrough middleware,
// its debug mode is invariably off and SetDebug is a no-op.
func (m *Middleware) SetDebug(b bool) {
	m.mu.Lock()
	if m.icfg != nil {
		m.icfg.debug = b
	}
	m.mu.Unlock()
}

// Config returns a copy of m's current configuration;
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
	icfg = m.icfg
	m.mu.RUnlock()
	return newConfig(icfg)
}
