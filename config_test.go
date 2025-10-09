package cors_test

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"slices"
	"testing"

	"github.com/jub0bs/cors"
	"github.com/jub0bs/cors/cfgerrors"
)

var cfgTypes = []reflect.Type{
	reflect.TypeFor[cors.Config](),
	reflect.TypeFor[cors.ExtraConfig](),
}

// We want our exported struct types to be incomparable because, otherwise,
// client code could rely on their comparability.
func TestIncomparability(t *testing.T) {
	for _, typ := range cfgTypes {
		f := func(t *testing.T) {
			if typ.Comparable() {
				t.Errorf("type %v is comparable, but should not be", typ)
			}
		}
		t.Run(typ.String(), f)
	}
}

// We don't want client code to rely on unkeyed literals
// of our exported struct types.
func TestImpossibilityOfUnkeyedStructLiterals(t *testing.T) {
	for _, typ := range cfgTypes {
		f := func(t *testing.T) {
			var unexportedFields bool
			for i := range typ.NumField() {
				if !typ.Field(i).IsExported() {
					unexportedFields = true
					break
				}
			}
			if !unexportedFields {
				t.Errorf("type %v has no unexported fields, but should have at least one", typ)
			}
		}
		t.Run(typ.String(), f)
	}
}

// Some clients rely on the ability to marshal configuration to JSON;
// see, for instance, https://github.com/rs/cors/pull/164.
func TestPossibilityToMarshalConfig(t *testing.T) {
	cfg := cors.Config{
		Origins:         []string{"https://example.com"},
		Credentialed:    true,
		Methods:         []string{http.MethodPost},
		RequestHeaders:  []string{"Authorization"},
		MaxAgeInSeconds: 30,
		ResponseHeaders: []string{"X-Response-Time"},
		ExtraConfig: cors.ExtraConfig{
			PreflightSuccessStatus: 299,
		},
	}
	enc := json.NewEncoder(io.Discard)
	if err := enc.Encode(cfg); err != nil {
		t.Error("cors.Config cannot be marshaled to JSON, but should be")
	}
}

func TestConfig(t *testing.T) {
	cases := []struct {
		desc string
		cfg  *cors.Config
		want *cors.Config
	}{
		{
			desc: "passthrough",
			cfg:  nil,
		}, {
			desc: "anonymous allow all",
			cfg: &cors.Config{
				Origins: []string{"*"},
				Methods: []string{"*"},
				RequestHeaders: []string{
					"authoriZation",
					"*",
					"Authorization",
				},
				ResponseHeaders: []string{"*"},
			},
			want: &cors.Config{
				Origins:         []string{"*"},
				Methods:         []string{"*"},
				RequestHeaders:  []string{"*", "authorization"},
				ResponseHeaders: []string{"*"},
			},
		}, {
			desc: "discrete methods discrete headers zero max age",
			cfg: &cors.Config{
				Origins: []string{
					"https://example.com",
					"https://example.com",
				},
				RequestHeaders: []string{
					"x-foO",
					"x-Bar",
					"authoRizaTion",
					"Authorization",
				},
				MaxAgeInSeconds: -1,
				ResponseHeaders: []string{
					"x-FOO",
					"X-baR",
					"x-foo",
				},
			},
			want: &cors.Config{
				Origins:         []string{"https://example.com"},
				RequestHeaders:  []string{"authorization", "x-bar", "x-foo"},
				MaxAgeInSeconds: -1,
				ResponseHeaders: []string{"x-bar", "x-foo"},
			},
		}, {
			desc: "credentialed all req headers",
			cfg: &cors.Config{
				Origins: []string{
					"http://example.com",
					"https://*.example.com:8080",
					"https://*.foo.example.com:8080",
				},
				Credentialed: true,
				Methods: []string{
					"POST",
					"PUT",
					"DELETE",
					"GET",
				},
				RequestHeaders:  []string{"*"},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{
					"x-FOO",
					"X-baR",
					"x-foo",
				},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus:             279,
					DangerouslyTolerateInsecureOrigins: true,
				},
			},
			want: &cors.Config{
				Origins: []string{
					"http://example.com",
					"https://*.example.com:8080",
				},
				Credentialed:    true,
				Methods:         []string{"DELETE", "PUT"},
				RequestHeaders:  []string{"*"},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{"x-bar", "x-foo"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus:             279,
					DangerouslyTolerateInsecureOrigins: true,
				},
			},
		}, {
			desc: "discrete origin patterns in addition to wildcard",
			cfg: &cors.Config{
				Origins: []string{
					"http://example.com",
					"http://example.com",
					"https://*.example.com",
					"https://*.example.com",
					"*",
					"*",
				},
			},
			want: &cors.Config{
				Origins: []string{"*"},
			},
		}, {
			desc: "safelisted response-header names",
			cfg: &cors.Config{
				Origins: []string{"http://example.com"},
				ResponseHeaders: []string{
					"Cache-Control",
					"content-Language",
					"content-lEngth",
					"content-typE",
					"expireS",
					"lasT-modified",
					"prAgmA",
					"X-Foo",
				},
			},
			want: &cors.Config{
				Origins:         []string{"http://example.com"},
				ResponseHeaders: []string{"x-foo"},
			},
		}, {
			desc: "discrete methods in addition to wildcard",
			cfg: &cors.Config{
				Origins: []string{"http://example.com"},
				Methods: []string{
					http.MethodDelete,
					http.MethodGet,
					http.MethodHead,
					http.MethodOptions,
					http.MethodPost,
					http.MethodPut,
					"PATCH",
					"*",
					"*",
				},
			},
			want: &cors.Config{
				Origins: []string{"http://example.com"},
				Methods: []string{"*"},
			},
		}, {
			desc: "browser-normalized methods",
			cfg: &cors.Config{
				Origins: []string{"http://example.com"},
				Methods: []string{
					"Get", "get", "gET",
					"Head", "head", "hEAD",
					"Post", "post", "pOST",
					//
					"getaway",
					"headstrong",
					"postal",
				},
			},
			want: &cors.Config{
				Origins: []string{"http://example.com"},
				Methods: []string{
					"getaway",
					"headstrong",
					"postal",
				},
			},
		}, {
			desc: "discrete request-header names in addition to wildcard (anonymous)",
			cfg: &cors.Config{
				Origins: []string{"http://example.com"},
				RequestHeaders: []string{
					"Authorization",
					"X-Api-Key",
					"*",
					"*",
					"AuthorizatioN",
				},
			},
			want: &cors.Config{
				Origins:        []string{"http://example.com"},
				RequestHeaders: []string{"*", "authorization"},
			},
		}, {
			desc: "discrete request-header names in addition to wildcard (credentialed)",
			cfg: &cors.Config{
				Origins:      []string{"https://example.com"},
				Credentialed: true,
				RequestHeaders: []string{
					"Authorization",
					"X-Api-Key",
					"*",
					"*",
					"AuthorizatioN",
				},
			},
			want: &cors.Config{
				Origins:        []string{"https://example.com"},
				Credentialed:   true,
				RequestHeaders: []string{"*"},
			},
		}, {
			desc: "discrete response-header names in addition to wildcard",
			cfg: &cors.Config{
				Origins: []string{"http://example.com"},
				ResponseHeaders: []string{
					"X-Foo",
					"X-Bar",
					"*",
					"*",
				},
			},
			want: &cors.Config{
				Origins:         []string{"http://example.com"},
				ResponseHeaders: []string{"*"},
			},
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			t.Parallel()
			var (
				mw  *cors.Middleware
				err error
			)
			if tc.cfg == nil {
				mw = new(cors.Middleware)
			} else {
				mw, err = cors.NewMiddleware(*tc.cfg)
				if err != nil {
					t.Fatalf("failure to build CORS middleware: %v", err)
				}
			}
			got := mw.Config()
			assertConfigEqual(t, got, tc.want)
		}
		t.Run(tc.desc, f)
	}
}

func assertConfigEqual(t *testing.T, got, want *cors.Config) {
	t.Helper()
	if got == nil && want != nil {
		t.Fatal("got nil *Config; want non-nil")
	}
	if got != nil && want == nil {
		t.Fatal("got non-nil *Config; want nil")
	}
	if want == nil {
		return
	}
	// origins
	if !slices.Equal(got.Origins, want.Origins) {
		t.Errorf("Origins: got %q; want %q", got.Origins, want.Origins)
	}
	// credentialed
	if got.Credentialed != want.Credentialed {
		const tmpl = "Credentialed: got %t; want %t"
		t.Errorf(tmpl, got.Credentialed, want.Credentialed)
	}
	// methods
	if !slices.Equal(got.Methods, want.Methods) {
		t.Errorf("Methods: got %q; want %q", got.Methods, want.Methods)
	}
	// request headers
	if !slices.Equal(got.RequestHeaders, want.RequestHeaders) {
		const tmpl = "RequestHeaders: got %q; want %q"
		t.Errorf(tmpl, got.RequestHeaders, want.RequestHeaders)
	}
	// max age
	if got.MaxAgeInSeconds != want.MaxAgeInSeconds {
		const tmpl = "MaxAgeInSeconds: got %d; want %d"
		t.Errorf(tmpl, got.MaxAgeInSeconds, want.MaxAgeInSeconds)
	}
	// response headers
	if !slices.Equal(got.ResponseHeaders, want.ResponseHeaders) {
		const tmpl = "ResponseHeaders: got %q; want %q"
		t.Errorf(tmpl, got.ResponseHeaders, want.ResponseHeaders)
	}
	// extra config
	if got.PreflightSuccessStatus != want.PreflightSuccessStatus {
		const tmpl = "PreflightSuccessStatus: got %d; want %d"
		t.Errorf(tmpl, got.PreflightSuccessStatus, want.PreflightSuccessStatus)
	}
	if got.DangerouslyTolerateInsecureOrigins != want.DangerouslyTolerateInsecureOrigins {
		const tmpl = "DangerouslyTolerateInsecureOrigins: got %t; want %t"
		t.Errorf(tmpl, got.DangerouslyTolerateInsecureOrigins, want.DangerouslyTolerateInsecureOrigins)
	}
	if got.DangerouslyTolerateSubdomainsOfPublicSuffixes != want.DangerouslyTolerateSubdomainsOfPublicSuffixes {
		const tmpl = "DangerouslyTolerateSubdomainsOfPublicSuffixes: got %t; want %t"
		t.Errorf(tmpl, got.DangerouslyTolerateSubdomainsOfPublicSuffixes, want.DangerouslyTolerateSubdomainsOfPublicSuffixes)
	}
}

type InvalidConfigTestCase struct {
	desc string
	cfg  *cors.Config
	want []*errorMatcher
}

var invalidConfigTestCases = []InvalidConfigTestCase{
	{
		desc: "no origin pattern specified",
		cfg:  &cors.Config{},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableOriginPatternError{Reason: "missing"}),
		},
	}, {
		desc: "null origin",
		cfg: &cors.Config{
			Origins: []string{"null"},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableOriginPatternError{
				Value:  "null",
				Reason: "prohibited",
			}),
		},
	}, {
		desc: "invalid origin pattern",
		cfg: &cors.Config{
			Origins: []string{"http://example.com:6060/path"},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableOriginPatternError{
				Value:  "http://example.com:6060/path",
				Reason: "invalid",
			}),
		},
	}, {
		desc: "empty method name",
		cfg: &cors.Config{
			Origins: []string{"https://example.com"},
			Methods: []string{""},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableMethodError{
				Value:  "",
				Reason: "invalid",
			}),
		},
	}, {
		desc: "invalid method name",
		cfg: &cors.Config{
			Origins: []string{"https://example.com"},
			Methods: []string{"résumé"},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableMethodError{
				Value:  "résumé",
				Reason: "invalid",
			}),
		},
	}, {
		desc: "forbidden method name",
		cfg: &cors.Config{
			Origins: []string{"https://example.com"},
			Methods: []string{
				http.MethodGet,
				http.MethodConnect,
			},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableMethodError{
				Value:  http.MethodConnect,
				Reason: "forbidden",
			}),
		},
	}, {
		desc: "empty request-header name",
		cfg: &cors.Config{
			Origins:        []string{"https://example.com"},
			RequestHeaders: []string{""},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableHeaderNameError{
				Value:  "",
				Type:   "request",
				Reason: "invalid",
			}),
		},
	}, {
		desc: "invalid request-header name",
		cfg: &cors.Config{
			Origins:        []string{"https://example.com"},
			RequestHeaders: []string{"résumé"},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableHeaderNameError{
				Value:  "résumé",
				Type:   "request",
				Reason: "invalid",
			}),
		},
	}, {
		desc: "forbidden request-header name",
		cfg: &cors.Config{
			Origins:        []string{"https://example.com"},
			RequestHeaders: []string{"Connection"},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableHeaderNameError{
				Value:  "Connection",
				Type:   "request",
				Reason: "forbidden",
			}),
		},
	}, {
		desc: "forbidden request-header name with Sec- prefix",
		cfg: &cors.Config{
			Origins:        []string{"https://example.com"},
			RequestHeaders: []string{"Sec-Foo"},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableHeaderNameError{
				Value:  "Sec-Foo",
				Type:   "request",
				Reason: "forbidden",
			}),
		},
	}, {
		desc: "forbidden request-header name with Proxy- prefix",
		cfg: &cors.Config{
			Origins:        []string{"https://example.com"},
			RequestHeaders: []string{"Proxy-Foo"},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableHeaderNameError{
				Value:  "Proxy-Foo",
				Type:   "request",
				Reason: "forbidden",
			}),
		},
	}, {
		desc: "prohibited request-header name",
		cfg: &cors.Config{
			Origins:        []string{"https://example.com"},
			RequestHeaders: []string{"Access-Control-Allow-Origin"},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableHeaderNameError{
				Value:  "Access-Control-Allow-Origin",
				Type:   "request",
				Reason: "prohibited",
			}),
		},
	}, {
		desc: "max age less than -1",
		cfg: &cors.Config{
			Origins: []string{"https://example.com"},
			RequestHeaders: []string{
				"Content-Type",
				"Authorization",
			},
			MaxAgeInSeconds: -2,
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.MaxAgeOutOfBoundsError{
				Value:   -2,
				Default: 5,
				Max:     86_400,
				Disable: -1,
			}),
		},
	}, {
		desc: "max age exceeds upper bound",
		cfg: &cors.Config{
			Origins: []string{"https://example.com"},
			RequestHeaders: []string{
				"Content-Type",
				"Authorization",
			},
			MaxAgeInSeconds: 86_401,
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.MaxAgeOutOfBoundsError{
				Value:   86_401,
				Default: 5,
				Max:     86_400,
				Disable: -1,
			}),
		},
	}, {
		desc: "empty response-header name",
		cfg: &cors.Config{
			Origins:         []string{"https://example.com"},
			ResponseHeaders: []string{""},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableHeaderNameError{
				Value:  "",
				Type:   "response",
				Reason: "invalid",
			}),
		},
	}, {
		desc: "invalid response-header name",
		cfg: &cors.Config{
			Origins:         []string{"https://example.com"},
			ResponseHeaders: []string{"résumé"},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableHeaderNameError{
				Value:  "résumé",
				Type:   "response",
				Reason: "invalid",
			}),
		},
	}, {
		desc: "forbidden response-header name",
		cfg: &cors.Config{
			Origins:         []string{"https://example.com"},
			ResponseHeaders: []string{"Set-Cookie"},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableHeaderNameError{
				Value:  "Set-Cookie",
				Type:   "response",
				Reason: "forbidden",
			}),
		},
	}, {
		desc: "prohibited response-header name",
		cfg: &cors.Config{
			Origins:         []string{"https://example.com"},
			ResponseHeaders: []string{"Access-Control-Request-Method"},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableHeaderNameError{
				Value:  "Access-Control-Request-Method",
				Type:   "response",
				Reason: "prohibited",
			}),
		},
	}, {
		desc: "preflight-success status less than 200",
		cfg: &cors.Config{
			Origins: []string{"https://example.com"},
			ExtraConfig: cors.ExtraConfig{
				PreflightSuccessStatus: 199,
			},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.PreflightSuccessStatusOutOfBoundsError{
				Value:   199,
				Default: 204,
				Min:     200,
				Max:     299,
			}),
		},
	}, {
		desc: "preflight-success status greater than 299",
		cfg: &cors.Config{
			Origins: []string{"https://example.com"},
			ExtraConfig: cors.ExtraConfig{
				PreflightSuccessStatus: 300,
			},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.PreflightSuccessStatusOutOfBoundsError{
				Value:   300,
				Default: 204,
				Min:     200,
				Max:     299,
			}),
		},
	}, {
		desc: "wildcard origin with Credentialed",
		cfg: &cors.Config{
			Origins:      []string{"*"},
			Credentialed: true,
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.IncompatibleOriginPatternError{
				Value:  "*",
				Reason: "credentialed",
			}),
		},
	}, {
		desc: "insecure origin with Credentialed without DangerouslyTolerateInsecureOrigins",
		cfg: &cors.Config{
			Origins: []string{
				"http://example.com:6060",
				"http://*.example.com:6060",
			},
			Credentialed: true,
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.IncompatibleOriginPatternError{
				Value:  "http://example.com:6060",
				Reason: "credentialed",
			}),
			newErrorMatcher(&cfgerrors.IncompatibleOriginPatternError{
				Value:  "http://*.example.com:6060",
				Reason: "credentialed",
			}),
		},
	}, {
		desc: "insecure origin with Credentialed without DangerouslyTolerateInsecureOrigins",
		cfg: &cors.Config{
			Origins: []string{
				"http://example.com:6060",
				"http://*.example.com:6060",
			},
			Credentialed: true,
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.IncompatibleOriginPatternError{
				Value:  "http://example.com:6060",
				Reason: "credentialed",
			}),
			newErrorMatcher(&cfgerrors.IncompatibleOriginPatternError{
				Value:  "http://*.example.com:6060",
				Reason: "credentialed",
			}),
		},
	}, {
		desc: "wildcard pattern encompassing subdomains of a public suffix without DangerouslyTolerateSubdomainsOfPublicSuffixes",
		cfg: &cors.Config{
			Origins: []string{"https://*.com"},
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.IncompatibleOriginPatternError{
				Value:  "https://*.com",
				Reason: "psl",
			}),
		},
	}, {
		desc: "wildcard response-header name with Credentialed",
		cfg: &cors.Config{
			Origins:         []string{"https://example.com"},
			Credentialed:    true,
			ResponseHeaders: []string{"*"},
		},
		want: []*errorMatcher{
			newErrorMatcher(new(cfgerrors.IncompatibleWildcardResponseHeaderNameError)),
		},
	}, {
		desc: "multiple configuration issues",
		cfg: &cors.Config{
			Origins: []string{
				"http://example.com",
				"https://example.com/",
			},
			Methods: []string{
				http.MethodConnect,
				"résumé",
			},
			RequestHeaders: []string{
				"résumé",
				"Access-Control-Allow-Origin",
			},
			MaxAgeInSeconds: 86_401,
		},
		want: []*errorMatcher{
			newErrorMatcher(&cfgerrors.UnacceptableOriginPatternError{
				Value:  "https://example.com/",
				Reason: "invalid",
			}),
			newErrorMatcher(&cfgerrors.UnacceptableMethodError{
				Value:  http.MethodConnect,
				Reason: "forbidden",
			}),
			newErrorMatcher(&cfgerrors.UnacceptableMethodError{
				Value:  "résumé",
				Reason: "invalid",
			}),
			newErrorMatcher(&cfgerrors.UnacceptableHeaderNameError{
				Value:  "résumé",
				Type:   "request",
				Reason: "invalid",
			}),
			newErrorMatcher(&cfgerrors.UnacceptableHeaderNameError{
				Value:  "Access-Control-Allow-Origin",
				Type:   "request",
				Reason: "prohibited",
			}),
			newErrorMatcher(&cfgerrors.MaxAgeOutOfBoundsError{
				Value:   86_401,
				Default: 5,
				Max:     86_400,
				Disable: -1,
			}),
		},
	},
}

func TestIncorrectConfig(t *testing.T) {
	for _, tc := range invalidConfigTestCases {
		f := func(t *testing.T) {
			mw, err := cors.NewMiddleware(*tc.cfg)
			if mw != nil {
				t.Error("got non-nil *Middleware; want nil *Middleware")
			}
			if err == nil {
				t.Error("got nil error; want non-nil error")
				return
			}
		iterationOverErrorTree: // O(m * n) isn't ideal, but ok.
			for err := range cfgerrors.All(err) {
				for i, m := range tc.want {
					if m == nil {
						continue
					}
					if m.matches(err) {
						tc.want[i] = nil // Mark as "matched".
						continue iterationOverErrorTree
					}
				}
				t.Errorf("unexpected error: %q", err)
			}
			for _, m := range tc.want {
				if m == nil { // Already matched.
					continue
				}
				t.Errorf("missing error:    %q", m.err)
			}
		}
		t.Run(tc.desc, f)
	}
}

type errorMatcher struct {
	matches func(error) bool
	err     error
}

// newErrorMatcher returns an errorMatcher that matches an error whose dynamic
// value is a pointer to a value equal to the value that ptrToTargetValue
// points to.
func newErrorMatcher[T comparable, P PError[T]](ptrToTargetValue P) *errorMatcher {
	pred := func(err error) bool {
		ptr, ok := err.(P)
		if !ok {
			return false
		}
		if ptrToTargetValue == nil {
			return ptr == nil
		}
		return ptr != nil && *ptrToTargetValue == *ptr
	}
	return &errorMatcher{
		matches: pred,
		err:     ptrToTargetValue,
	}
}

// An PError[T] is an error of dynamic type *T.
type PError[T any] interface {
	error
	*T
}

func BenchmarkIncorrectConfig(b *testing.B) {
	for _, tc := range invalidConfigTestCases {
		f := func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if _, err := cors.NewMiddleware(*tc.cfg); err == nil {
					b.Fatal("got nil error; want non-nil error")
				}
			}
		}
		b.Run(tc.desc, f)
	}
}
