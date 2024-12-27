package cors_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jub0bs/cors"
)

func BenchmarkMiddleware(b *testing.B) {
	cases := []MiddlewareTestCase{
		{
			desc:       "no CORS",
			newHandler: newDummyHandler(),
			cases: []ReqTestCase{
				{
					desc:      "preflight",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"authorization"},
					},
				}, {
					desc:      "actual",
					reqMethod: http.MethodGet,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				},
			},
		}, {
			desc:       "single origin some req headers",
			newHandler: newDummyHandler(),
			cfg: &cors.Config{
				Origins:        []string{"https://example.com"},
				RequestHeaders: requestHeadersAllowedByDefaultInRsCORS,
			},
			cases: []ReqTestCase{
				{
					desc:      "preflight from allowed",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"authorization"},
					},
				}, {
					desc:      "actual from allowed",
					reqMethod: http.MethodGet,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				}, {
					desc:      "preflight from disallowed",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.computer"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"authorization"},
					},
				}, {
					desc:      "actual from disallowed",
					reqMethod: http.MethodGet,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.computer"},
					},
				}, {
					desc:      "preflight with adversarial ACRH: same allowed name repeated many times",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {strings.Repeat("accept,", http.DefaultMaxHeaderBytes/len("accept,"))},
					},
				}, {
					desc:      "preflight with adversarial ACRH: lots of OWS",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"accept," + strings.Repeat(" ", http.DefaultMaxHeaderBytes) + "content-type"},
					},
				}, {
					desc:      "preflight with adversarial ACRH: lots of empty ACRH lines",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   make([]string, 1024),
					},
				},
			},
		}, {
			desc:       "multiple origins some req headers",
			newHandler: newDummyHandler(),
			cfg: &cors.Config{
				Origins:        severalOrigins,
				RequestHeaders: requestHeadersAllowedByDefaultInRsCORS,
			},
			cases: []ReqTestCase{
				{
					desc:      "preflight from allowed",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"authorization"},
					},
				}, {
					desc:      "actual from allowed",
					reqMethod: http.MethodGet,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				}, {
					desc:      "preflight from disallowed",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.computer"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"authorization"},
					},
				}, {
					desc:      "actual from disallowed",
					reqMethod: http.MethodGet,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.computer"},
					},
				},
			},
		}, {
			desc:       "two pathological origins some req headers",
			newHandler: newDummyHandler(),
			cfg: &cors.Config{
				Origins: []string{
					"https://a" + strings.Repeat(".a", hostMaxLen/2),
					"https://b" + strings.Repeat(".a", hostMaxLen/2),
				},
				RequestHeaders: requestHeadersAllowedByDefaultInRsCORS,
			},
			cases: []ReqTestCase{
				{
					desc:      "preflight",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://a" + strings.Repeat(".a", hostMaxLen/2)},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"authorization"},
					},
				}, {
					desc:      "actual",
					reqMethod: http.MethodGet,
					reqHeaders: http.Header{
						headerOrigin: {"https://a" + strings.Repeat(".a", hostMaxLen/2)},
					},
				}, {
					desc:      "preflight from disallowed",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://c" + strings.Repeat(".a", hostMaxLen/2)},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"authorization"},
					},
				}, {
					desc:      "actual from disallowed",
					reqMethod: http.MethodGet,
					reqHeaders: http.Header{
						headerOrigin: {"https://c" + strings.Repeat(".a", hostMaxLen/2)},
					},
				},
			},
		}, {
			desc:       "many origins some req headers",
			newHandler: newDummyHandler(),
			cfg: &cors.Config{
				Origins:        manyOrigins,
				RequestHeaders: requestHeadersAllowedByDefaultInRsCORS,
			},
			cases: []ReqTestCase{
				{
					desc:      "preflight",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {manyOrigins[0]},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"authorization"},
					},
				}, {
					desc:      "actual",
					reqMethod: http.MethodGet,
					reqHeaders: http.Header{
						headerOrigin: {manyOrigins[0]},
					},
				}, {
					desc:      "preflight from disallowed",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.computer"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"authorization"},
					},
				}, {
					desc:      "actual from disallowed",
					reqMethod: http.MethodGet,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.computer"},
					},
				},
			},
		}, {
			desc:       "credentialed any req headers",
			newHandler: newDummyHandler(),
			cfg: &cors.Config{
				Origins:        []string{"https://example.com"},
				Credentialed:   true,
				RequestHeaders: []string{"*"}, //, "Authorization"},
			},
			cases: []ReqTestCase{
				{
					desc:      "preflight",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"authorization"},
					},
				}, {
					desc:      "preflight with adversarial ACRH: same allowed name repeated many times",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {strings.Repeat("a,", http.DefaultMaxHeaderBytes/len("a,"))},
					},
				}, {
					desc:      "preflight with adversarial ACRH: lots of OWS",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"a," + strings.Repeat(" ", http.DefaultMaxHeaderBytes) + "b"},
					},
				}, {
					desc:      "preflight with adversarial ACRH: lots of empty ACRH lines",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   make([]string, 1024),
					},
				}, {
					desc:      "actual",
					reqMethod: http.MethodGet,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				},
			},
		}, {
			desc:       "no CORS, outer Vary",
			outerMw:    &varyMiddleware,
			newHandler: newDummyHandler(),
			cases: []ReqTestCase{
				{
					desc:      "preflight",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"authorization"},
					},
				}, {
					desc:      "actual",
					reqMethod: http.MethodGet,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				},
			},
		}, {
			desc:       "outer Vary",
			outerMw:    &varyMiddleware,
			newHandler: newDummyHandler(),
			cfg: &cors.Config{
				Origins:        []string{"https://example.com"},
				Credentialed:   true,
				RequestHeaders: []string{"*", "Authorization"},
			},
			cases: []ReqTestCase{
				{
					desc:      "preflight",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"authorization"},
					},
				}, {
					desc:      "preflight with adversarial ACRH: same allowed name repeated many times",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {strings.Repeat("a,", http.DefaultMaxHeaderBytes/len("a,"))},
					},
				}, {
					desc:      "preflight with adversarial ACRH: lots of OWS",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   {"a," + strings.Repeat(" ", http.DefaultMaxHeaderBytes) + "b"},
					},
				}, {
					desc:      "preflight with adversarial ACRH: lots of empty ACRH lines",
					reqMethod: http.MethodOptions,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {http.MethodGet},
						headerACRH:   make([]string, 1024),
					},
				}, {
					desc:      "actual",
					reqMethod: http.MethodGet,
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				},
			},
		},
	}

	for _, mwbc := range cases {
		if mwbc.cfg == nil {
			continue
		}
		var mw *cors.Middleware
		// benchmark initialization
		f := func(b *testing.B) {
			b.ReportAllocs()
			var err error
			for range b.N {
				mw, err = cors.NewMiddleware(*mwbc.cfg)
				if err != nil {
					b.Fatal(err)
				}
			}
		}
		b.Run("initialization "+mwbc.desc, f)

		// benchmark config
		f = func(b *testing.B) {
			if mw == nil { // in case subbenchmark 'initialization' wasn't run
				var err error
				mw, err = cors.NewMiddleware(*mwbc.cfg)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				mw.Config()
			}
		}
		b.Run("config         "+mwbc.desc, f)
	}

	// benchmark execution
	for _, mwbc := range cases {
		var handler http.Handler = mwbc.newHandler()
		var mw *cors.Middleware
		if mwbc.cfg != nil {
			var err error
			mw, err = cors.NewMiddleware(*mwbc.cfg)
			if err != nil {
				b.Fatal(err)
			}
			handler = mw.Wrap(handler)
		}
		if mwbc.outerMw != nil {
			handler = mwbc.outerMw.Wrap(handler)
		}
		for _, bc := range mwbc.cases {
			f := func(b *testing.B) {
				req := newRequest(bc.reqMethod, bc.reqHeaders)
				b.ReportAllocs()
				b.ResetTimer()
				// We run benchmarks in parallel because typical workloads
				// for HTTP handlers are concurrent.
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, req)
					}
				})
			}
			desc := fmt.Sprintf("exec       %s vs %s", mwbc.desc, bc.desc)
			if mw == nil {
				b.Run(desc, f)
				continue
			}
			// Run the benchmark outside debug mode.
			mw.SetDebug(false)
			b.Run(desc, f)
			// Run the benchmark in debug mode.
			desc = fmt.Sprintf("exec debug %s vs %s", mwbc.desc, bc.desc)
			mw.SetDebug(true)
			b.Run(desc, f)
		}
	}
}

// see https://github.com/rs/cors/blob/1562b1715b353146f279ff7d445b7412e0f1a842/cors.go#L197
var requestHeadersAllowedByDefaultInRsCORS = []string{
	"Accept",
	"Content-Type",
	"X-Requested-With",
}

var severalOrigins = []string{
	"https://example.com",
	"https://*.example.com",
	"https://google.com",
	"https://*.google.com",
}

const hostMaxLen = 253

var manyOrigins []string

func init() {
	const n = 100
	for i := range n {
		manyOrigins = append(
			manyOrigins,
			// https
			fmt.Sprintf("https://%d.example.com", i),
			fmt.Sprintf("https://%d.example.com:7070", i),
			fmt.Sprintf("https://%d.example.com:8080", i),
			fmt.Sprintf("https://%d.example.com:9090", i),
			// one subdomain deep
			fmt.Sprintf("https://%d.foo.example.com", i),
			fmt.Sprintf("https://%d.foo.example.com:6060", i),
			fmt.Sprintf("https://%d.foo.example.com:7070", i),
			fmt.Sprintf("https://%d.foo.example.com:9090", i),
			// two subdomains deep
			fmt.Sprintf("https://%d.foo.bar.example.com", i),
			fmt.Sprintf("https://%d.foo.bar.example.com:6060", i),
			fmt.Sprintf("https://%d.foo.bar.example.com:7070", i),
			fmt.Sprintf("https://%d.foo.bar.example.com:9090", i),
			// arbitrary subdomains
			"https://*.foo.bar.example.com",
			"https://*.foo.bar.example.com:6060",
			"https://*.foo.bar.example.com:7070",
			"https://*.foo.bar.example.com:9090",
		)
	}
}

var dummyHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	io.WriteString(w, "Hello, World!")
})

func newDummyHandler() func() http.Handler {
	return func() http.Handler {
		return dummyHandler
	}
}
