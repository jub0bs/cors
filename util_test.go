package cors_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jub0bs/cors"
)

const (
	// common request headers
	headerOrigin = "Origin"

	// preflight-only request headers
	headerACRM = "Access-Control-Request-Method"
	headerACRH = "Access-Control-Request-Headers"

	// common response headers
	headerACAO = "Access-Control-Allow-Origin"
	headerACAC = "Access-Control-Allow-Credentials"

	// preflight-only response headers
	headerACAM = "Access-Control-Allow-Methods"
	headerACAH = "Access-Control-Allow-Headers"
	headerACMA = "Access-Control-Max-Age"

	// actual-only response headers
	headerACEH = "Access-Control-Expose-Headers"

	headerVary = "Vary"
)

const (
	varyPreflightValue = headerACRH + ", " + headerACRM + ", " + headerOrigin
	wildcard           = "*"
	wildcardAndAuth    = "*,authorization"
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
	reqHeaders http.Header
	// expectations
	preflight                bool
	preflightPassesCORSCheck bool
	preflightFails           bool
	respHeaders              http.Header
}

func newRequest(method string, headers http.Header) *http.Request {
	const dummyEndpoint = "https://example.com/whatever"
	req := httptest.NewRequest(method, dummyEndpoint, nil)
	// Because our middleware don't modify requests, headers can be shared.
	req.Header = headers
	return req
}

type spyHandler struct {
	called      atomic.Bool
	statusCode  int
	respHeaders http.Header
	body        string
	handler     http.Handler
}

func newSpyHandler(statusCode int, respHeaders http.Header, body string) func() http.Handler {
	f := func() http.Handler {
		h := func(w http.ResponseWriter, _ *http.Request) {
			for k, v := range respHeaders {
				w.Header()[k] = append(w.Header()[k], v...)
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
	hdrs: http.Header{headerVary: {"before"}},
}

type middleware struct {
	hdrs http.Header
}

func (m middleware) Wrap(next http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		for k, v := range m.hdrs {
			w.Header()[k] = append(w.Header()[k], v...)
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
	default:
		wantStatusCode = http.StatusNoContent
	}
	if gotStatus != wantStatusCode {
		const tmpl = "got %d; want status code %d"
		t.Errorf(tmpl, gotStatus, wantStatusCode)
	}
}

// note: this function mutates got (to ease subsequent assertions)
func assertResponseHeaders(t *testing.T, gotHeaders, wantHeaders http.Header) {
	t.Helper()
	for name, want := range wantHeaders {
		listBased := isListBasedField(name)
		got := gotHeaders[name]
		if !listBased { // name is a singleton field
			if !slices.Equal(got, want) {
				t.Errorf("Response header %q = %q, want %q", name, got, want)
				continue
			}
			delete(gotHeaders, name)
			continue
		}
		// name is a list-based field
		if !deleteKV(gotHeaders, name, want) {
			t.Errorf("Response header %q = %q, want %q", name, got, want)
			continue
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

func deleteKV(h http.Header, k string, v []string) bool {
	vh, found := h[k]
	if !found {
		return false
	}
	if !isListBasedField(k) { // k is a singleton field
		return slices.Equal(h[k], v)
	}
	// k is a list-based field
	v = normalize(v)
	vh = normalize(vh)
	if len(vh) < len(v) {
		return false
	}
	for i := range len(vh) - len(v) + 1 {
		if !slices.Equal(v, vh[i:i+len(v)]) {
			continue
		}
		vh = slices.Delete(vh, i, i+len(v))
		h[k] = vh
		if len(vh) == 0 {
			delete(h, k)
		}
		return true
	}
	return false
}

// isListBasedField reports whether name is a list-based field (i.e. not a singleton field);
// see https://httpwg.org/specs/rfc9110.html#abnf.extension.
func isListBasedField(name string) bool {
	switch name {
	case "Vary":
		// see https://www.rfc-editor.org/rfc/rfc9110#section-12.5.5
		return true
	case "Access-Control-Allow-Origin":
		// see https://fetch.spec.whatwg.org/#http-new-header-syntax
		return false
	case "Access-Control-Allow-Credentials":
		// see https://fetch.spec.whatwg.org/#http-new-header-syntax
		return false
	case "Access-Control-Expose-Headers":
		// see https://fetch.spec.whatwg.org/#http-new-header-syntax
		return true
	case "Access-Control-Max-Age":
		// see https://fetch.spec.whatwg.org/#http-new-header-syntax
		return false
	case "Access-Control-Allow-Methods":
		// see https://fetch.spec.whatwg.org/#http-new-header-syntax
		return true
	case "Access-Control-Allow-Headers":
		// see https://fetch.spec.whatwg.org/#http-new-header-syntax
		return true
	default: // assume singleton field
		return false
	}
}

func normalize(s []string) (res []string) {
	const owsChars = " \t"
	for _, str := range s {
		for e := range strings.SplitSeq(str, ",") {
			e = strings.Trim(e, owsChars)
			res = append(res, e)
		}
	}
	return
}

func newMutatingHandler() http.Handler {
	f := func(w http.ResponseWriter, _ *http.Request) {
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
