package cors_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/jub0bs/cors"
)

const (
	// common request headers
	headerOrigin = "Origin"

	// preflight-only request headers
	headerACRPN = "Access-Control-Request-Private-Network"
	headerACRM  = "Access-Control-Request-Method"
	headerACRH  = "Access-Control-Request-Headers"

	// common response headers
	headerACAO = "Access-Control-Allow-Origin"
	headerACAC = "Access-Control-Allow-Credentials"

	// preflight-only response headers
	headerACAPN = "Access-Control-Allow-Private-Network"
	headerACAM  = "Access-Control-Allow-Methods"
	headerACAH  = "Access-Control-Allow-Headers"
	headerACMA  = "Access-Control-Max-Age"

	// actual-only response headers
	headerACEH = "Access-Control-Expose-Headers"

	headerVary = "Vary"
)

const (
	varyPreflightValue = headerACRH + ", " + headerACRM + ", " +
		headerACRPN + ", " + headerOrigin

	wildcard        = "*"
	wildcardAndAuth = "*,authorization"
)

type MiddlewareTestCase struct {
	desc       string
	outerMw    *middleware
	newHandler func() http.Handler
	cfg        *cors.Config
	invalid    bool
	debug      bool
	cases      []ReqTestCase
}

type ReqTestCase struct {
	desc string
	// request
	reqMethod  string
	reqHeaders Headers
	// expectations
	preflight                bool
	preflightPassesCORSCheck bool
	preflightFails           bool
	respHeaders              Headers
}

// Headers represent a set of HTTP-header name-value pairs
// in which there are no duplicate names.
type Headers = map[string]string

func newRequest(method string, headers Headers) *http.Request {
	const dummyEndpoint = "https://example.com/whatever"
	req := httptest.NewRequest(method, dummyEndpoint, nil)
	for name, value := range headers {
		req.Header.Add(name, value)
	}
	return req
}

type spyHandler struct {
	called      atomic.Bool
	statusCode  int
	respHeaders Headers
	body        string
	handler     http.Handler
}

func newSpyHandler(statusCode int, respHeaders Headers, body string) func() http.Handler {
	f := func() http.Handler {
		h := func(w http.ResponseWriter, r *http.Request) {
			for k, v := range respHeaders {
				w.Header().Add(k, v)
			}
			w.WriteHeader(statusCode)
			if len(body) > 0 {
				io.WriteString(w, body)
			}
		}
		return &spyHandler{
			statusCode:  statusCode,
			respHeaders: respHeaders,
			body:        body,
			handler:     http.HandlerFunc(h),
		}
	}
	return f
}

func (s *spyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.called.Store(true)
	s.handler.ServeHTTP(w, r)
}

var varyMiddleware = middleware{
	hdrs: Headers{headerVary: "before"},
}

type middleware struct {
	hdrs Headers
}

func (m middleware) Wrap(next http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		for k, v := range m.hdrs {
			w.Header().Add(k, v)
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(f)
}

func assertPreflightStatus(t *testing.T, spyStatus, gotStatus int, mwtc *MiddlewareTestCase, tc *ReqTestCase) {
	t.Helper()
	var wantStatusCode int
	switch {
	case mwtc.cfg == nil:
		wantStatusCode = spyStatus
	case !tc.preflightPassesCORSCheck || !mwtc.debug && tc.preflightFails:
		wantStatusCode = http.StatusForbidden
	case mwtc.cfg.PreflightSuccessStatus == 0:
		wantStatusCode = http.StatusNoContent
	default:
		wantStatusCode = mwtc.cfg.PreflightSuccessStatus
	}
	if gotStatus != wantStatusCode {
		const tmpl = "got %d; want status code %d"
		t.Errorf(tmpl, gotStatus, wantStatusCode)
	}
}

// note: this function mutates got (to ease subsequent assertions)
func assertResponseHeaders(t *testing.T, got http.Header, want Headers) {
	t.Helper()
	for k, v := range want {
		if !deleteHeaderValue(got, k, v) {
			t.Errorf(`missing header value "%s: %s"`, k, v)
		}
		// clean up: remove headers whose values are empty but non-nil
		if vs, found := got[k]; found && len(vs) == 0 {
			delete(got, k)
		}
	}
}

func assertNoMoreResponseHeaders(t *testing.T, left http.Header) {
	t.Helper()
	for k, v := range left {
		t.Errorf("unexpected header value(s) %q: %q", k, v)
	}
}

func assertBody(t *testing.T, body io.ReadCloser, want string) {
	t.Helper()
	var buf bytes.Buffer
	_, err := io.Copy(&buf, body)
	if got := buf.String(); err != nil || got != want {
		t.Errorf("got body %q; want body %q", got, want)
	}
}

// deleteHeaderValue reports whether h contains a header named key
// that contains value.
// If that's the case, the key-value pair in question is removed from h.
func deleteHeaderValue(h http.Header, key, value string) bool {
	vs, ok := h[key]
	if !ok {
		return false
	}
	i := slices.Index(vs, value)
	if i == -1 {
		return false
	}
	h[key] = slices.Delete(vs, i, i+1)
	return true
}

func newMutatingHandler() http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		resHdrs := w.Header()
		keys := []string{
			headerACAO,
			headerACAC,
			headerACEH,
			headerVary,
		}
		for _, k := range keys {
			if v, ok := resHdrs[k]; ok && len(v) > 0 {
				v[0] = "mutated!"
			}
		}
	}
	return http.HandlerFunc(f)
}
