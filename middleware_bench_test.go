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
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   http.MethodGet,
						headerACRH:   "authorization",
					},
				}, {
					desc:      "actual",
					reqMethod: http.MethodGet,
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
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
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   http.MethodGet,
						headerACRH:   "authorization",
					},
				}, {
					desc:      "actual from allowed",
					reqMethod: http.MethodGet,
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
				}, {
					desc:      "preflight from disallowed",
					reqMethod: http.MethodOptions,
					reqHeaders: Headers{
						headerOrigin: "https://example.computer",
						headerACRM:   http.MethodGet,
						headerACRH:   "authorization",
					},
				}, {
					desc:      "actual from disallowed",
					reqMethod: http.MethodGet,
					reqHeaders: Headers{
						headerOrigin: "https://example.computer",
					},
				}, {
					desc:      "preflight with adversarial ACRH",
					reqMethod: http.MethodOptions,
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   http.MethodGet,
						headerACRH:   strings.Repeat("a,", 1024),
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
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   http.MethodGet,
						headerACRH:   "authorization",
					},
				}, {
					desc:      "actual from allowed",
					reqMethod: http.MethodGet,
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
				}, {
					desc:      "preflight from disallowed",
					reqMethod: http.MethodOptions,
					reqHeaders: Headers{
						headerOrigin: "https://example.computer",
						headerACRM:   http.MethodGet,
						headerACRH:   "authorization",
					},
				}, {
					desc:      "actual from disallowed",
					reqMethod: http.MethodGet,
					reqHeaders: Headers{
						headerOrigin: "https://example.computer",
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
					reqHeaders: Headers{
						headerOrigin: "https://a" + strings.Repeat(".a", hostMaxLen/2),
						headerACRM:   http.MethodGet,
						headerACRH:   "authorization",
					},
				}, {
					desc:      "actual",
					reqMethod: http.MethodGet,
					reqHeaders: Headers{
						headerOrigin: "https://a" + strings.Repeat(".a", hostMaxLen/2),
					},
				}, {
					desc:      "preflight from disallowed",
					reqMethod: http.MethodOptions,
					reqHeaders: Headers{
						headerOrigin: "https://c" + strings.Repeat(".a", hostMaxLen/2),
						headerACRM:   http.MethodGet,
						headerACRH:   "authorization",
					},
				}, {
					desc:      "actual from disallowed",
					reqMethod: http.MethodGet,
					reqHeaders: Headers{
						headerOrigin: "https://c" + strings.Repeat(".a", hostMaxLen/2),
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
					reqHeaders: Headers{
						headerOrigin: manyOrigins[0],
						headerACRM:   http.MethodGet,
						headerACRH:   "authorization",
					},
				}, {
					desc:      "actual",
					reqMethod: http.MethodGet,
					reqHeaders: Headers{
						headerOrigin: manyOrigins[0],
					},
				}, {
					desc:      "preflight from disallowed",
					reqMethod: http.MethodOptions,
					reqHeaders: Headers{
						headerOrigin: "https://example.computer",
						headerACRM:   http.MethodGet,
						headerACRH:   "authorization",
					},
				}, {
					desc:      "actual from disallowed",
					reqMethod: http.MethodGet,
					reqHeaders: Headers{
						headerOrigin: "https://example.computer",
					},
				},
			},
		}, {
			desc:       "credentialed any req headers",
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
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   http.MethodGet,
						headerACRH:   "authorization",
					},
				}, {
					desc:      "preflight with adversarial ACRH",
					reqMethod: http.MethodOptions,
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   http.MethodGet,
						headerACRH:   strings.Repeat("a,", 1024),
					},
				}, {
					desc:      "actual",
					reqMethod: http.MethodGet,
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
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
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   http.MethodGet,
						headerACRH:   "authorization",
					},
				}, {
					desc:      "actual",
					reqMethod: http.MethodGet,
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
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
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   http.MethodGet,
						headerACRH:   "authorization",
					},
				}, {
					desc:      "preflight with adversarial ACRH",
					reqMethod: http.MethodOptions,
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   http.MethodGet,
						headerACRH:   strings.Repeat("a,", 1024),
					},
				}, {
					desc:      "actual",
					reqMethod: http.MethodGet,
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
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
			b.ReportAllocs()
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
			if mwbc.debug {
				mw.SetDebug(true)
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
			b.Run(desc, f)

			if mwbc.cfg == nil {
				continue // no more work to do if no CORS middleware
			}
			mw.SetDebug(true)
			desc = fmt.Sprintf("exec debug %s vs %s", mwbc.desc, bc.desc)
			b.Run(desc, f)
		}
	}
}

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
	for i := 0; i < n; i++ {
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

var dummyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "Hello, World!")
})

func newDummyHandler() func() http.Handler {
	return func() http.Handler {
		return dummyHandler
	}
}
