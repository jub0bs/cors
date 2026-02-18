package cors_test

import (
	"bytes"
	"cmp"
	"crypto/rand"
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
	desc            string
	reqMethod       string
	reqHeaders      http.Header
	wantOutcome     ReqOutcome
	wantRespHeaders http.Header
}

type ReqOutcome uint8

const (
	isActual ReqOutcome = iota
	isPreflightAndFailsDuringCORSCheck
	isPreflightAndFailsAfterCORSCheck
	isPreflightAndSucceeds
)

func (ro ReqOutcome) isPreflight() bool {
	switch ro {
	case isPreflightAndFailsDuringCORSCheck,
		isPreflightAndFailsAfterCORSCheck,
		isPreflightAndSucceeds:
		return true
	default:
		return false
	}
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

func newSpyHandler(
	statusCode int,
	respHeaders http.Header,
	body string,
) func() http.Handler {
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

func assertPreflightStatus(
	t *testing.T,
	spyStatus int,
	gotStatus int,
	mwtc *MiddlewareTestCase,
	tc *ReqTestCase,
) {
	t.Helper()
	var wantStatusCode int
	switch {
	case mwtc.cfg == nil,
		tc.wantOutcome == isActual:
		wantStatusCode = spyStatus
	case tc.wantOutcome == isPreflightAndFailsDuringCORSCheck,
		!mwtc.debug && tc.wantOutcome == isPreflightAndFailsAfterCORSCheck:
		wantStatusCode = http.StatusForbidden // keep in sync with preflightFailStatus
	default:
		wantStatusCode = http.StatusNoContent // keep in sync with preflightOKStatus
	}
	if gotStatus != wantStatusCode {
		const tmpl = "got %d; want status code %d"
		t.Errorf(tmpl, gotStatus, wantStatusCode)
	}
}

// assertHeadersEqual checks that gotHeader contains the union of all of
// wantHeaders and nothing more. It is insensitive to the order of elements of
// values of list-based header fields.
func assertHeadersEqual(
	t *testing.T,
	gotHeader http.Header,
	wantHeaders ...http.Header,
) {
	t.Helper()
	// Produce a normalized copy of gotHeader that we can safely mutate.
	gotHeader = coalesce(t, gotHeader)
	for name, want := range coalesce(t, wantHeaders...) {
		got, found := gotHeader[name]
		if !found {
			const tmpl = "missing header %q: %q"
			t.Errorf(tmpl, name, want)
			continue
		}
		if !isListBasedField(name) {
			if !slices.Equal(got, want) {
				const tmpl = "header %q: got %q; want %q"
				t.Errorf(tmpl, name, got, want)
			}
			delete(gotHeader, name)
			continue
		}
		// Perform a detailed diff of want versus got.
		const (
			missingElemTmpl = "header %q does not list %q but should"
			extraElemTmpl   = "header %q lists %q but should not"
		)
		var i, j int
	diffLoop:
		for {
			switch {
			case i < len(got) && j < len(want):
				switch cmp.Compare(got[i], want[j]) {
				case -1:
					t.Errorf(extraElemTmpl, name, got[i])
					i++
				case 0:
					i, j = i+1, j+1
				case +1:
					t.Errorf(missingElemTmpl, name, want[j])
					j++
				}
			case i < len(got) && j >= len(want):
				t.Errorf(extraElemTmpl, name, got[i])
				i++
			case i >= len(got) && j < len(want):
				t.Errorf(missingElemTmpl, name, want[j])
				j++
			default:
				break diffLoop
			}
		}
		delete(gotHeader, name)
	}
	// Assert that gotHeader is now empty.
	for name, vs := range gotHeader {
		const tmpl = "unexpected header %q: %q"
		t.Errorf(tmpl, name, vs)
	}
}

// isListBasedField reports whether name is a known list-based response header
// field (i.e. not a singleton header field).
// See https://httpwg.org/specs/rfc9110.html#abnf.extension.
func isListBasedField(name string) bool {
	switch name {
	case
		// see https://www.rfc-editor.org/rfc/rfc9110#section-12.5.5
		headerVary,
		// see https://fetch.spec.whatwg.org/#http-new-header-syntax
		headerACAM,
		headerACAH,
		headerACEH:
		return true
	case
		// see https://fetch.spec.whatwg.org/#http-new-header-syntax
		headerACAO,
		headerACAC,
		headerACMA:
		return false
	default: // assume a singleton header field
		return false
	}
}

// coalesce normalizes and merges all the name-value pairs of hs in a single
// http.Header and returns the result. The values of each list-based field are
// sorted and freed of duplicate elements. If a conflict between the values of
// a singleton field occurs, coalesce fails.
func coalesce(t *testing.T, hs ...http.Header) http.Header {
	t.Helper()
	res := make(http.Header)
	for _, h := range hs {
		for name, vs := range h {
			if isListBasedField(name) {
				var vs2 []string
				for _, v := range vs {
					for e := range strings.SplitSeq(v, ",") {
						// Trim optional whitespace around e;
						// see https://httpwg.org/specs/rfc9110.html#abnf.extension,
						// https://httpwg.org/specs/rfc9110.html#whitespace, and
						// https://fetch.spec.whatwg.org/#header-value-get-decode-and-split.
						const owsChars = " \t"
						e = strings.Trim(e, owsChars)
						vs2 = append(vs2, e)
					}
				}
				res[name] = append(res[name], vs2...)
			} else { // name is assumed to be a singleton header field
				if len(res[name]) != 0 {
					const tmpl = "conflicting values for singleton (?) header %q: current %q; incoming %q"
					t.Fatalf(tmpl, name, res[name], vs)
				}
				res[name] = vs
			}
		}
	}
	// Sort and compact the value of each list-based field.
	for name, vs := range res {
		if !isListBasedField(name) {
			continue
		}
		slices.Sort(vs)
		res[name] = slices.Compact(vs)
	}
	return res
}

func assertBodyEqual(t *testing.T, body io.ReadCloser, want string) {
	t.Helper()
	defer body.Close()
	var buf bytes.Buffer
	_, err := io.Copy(&buf, body)
	if got := buf.String(); err != nil || got != want {
		t.Errorf("got body %q; want body %q", got, want)
	}
}

func newMutatingHandler() http.Handler {
	keys := []string{
		headerACAO,
		headerACAC,
		headerACEH,
		headerVary,
	}
	f := func(w http.ResponseWriter, _ *http.Request) {
		resHdrs := w.Header()
		for _, k := range keys {
			if v, ok := resHdrs[k]; ok && len(v) > 0 {
				v[0] = rand.Text()
			}
		}
	}
	return http.HandlerFunc(f)
}
