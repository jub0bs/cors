package cors_test

import (
	"encoding/json"
	"io"
	"iter"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"testing"

	"github.com/jub0bs/cors"
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
			PrivateNetworkAccess: true,
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
				Origins:         []string{"*"},
				Methods:         []string{"*"},
				RequestHeaders:  []string{"authoriZation", "*"},
				ResponseHeaders: []string{"*"},
			},
			want: &cors.Config{
				Origins:         []string{"*"},
				Methods:         []string{"*"},
				RequestHeaders:  []string{"*", "authorization"},
				ResponseHeaders: []string{"*"},
			},
		}, {
			desc: "discrete methods discrete headers zero max age PNAnoCORS",
			cfg: &cors.Config{
				Origins: []string{
					"https://example.com",
					"https://example.com",
				},
				RequestHeaders:  []string{"x-foO", "x-Bar", "authoRizaTion"},
				MaxAgeInSeconds: -1,
				ResponseHeaders: []string{"x-FOO", "X-baR", "x-foo"},
				ExtraConfig: cors.ExtraConfig{
					PrivateNetworkAccessInNoCORSModeOnly: true,
				},
			},
			want: &cors.Config{
				Origins:         []string{"https://example.com"},
				RequestHeaders:  []string{"authorization", "x-bar", "x-foo"},
				MaxAgeInSeconds: -1,
				ResponseHeaders: []string{"x-bar", "x-foo"},
				ExtraConfig: cors.ExtraConfig{
					PrivateNetworkAccessInNoCORSModeOnly: true,
				},
			},
		}, {
			desc: "credentialed all req headers",
			cfg: &cors.Config{
				Origins: []string{
					"http://example.com",
					"https://*.example.com:8080",
					"https://*.foo.example.com:8080",
				},
				Credentialed:    true,
				Methods:         []string{"POST", "PUT", "DELETE", "GET"},
				RequestHeaders:  []string{"*"},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{"x-FOO", "X-baR", "x-foo"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus:             279,
					PrivateNetworkAccess:               true,
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
					PrivateNetworkAccess:               true,
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
	if got.PrivateNetworkAccess != want.PrivateNetworkAccess {
		const tmpl = "PrivateNetworkAccess: got %t; want %t"
		t.Errorf(tmpl, got.PrivateNetworkAccess, want.PrivateNetworkAccess)
	}
	if got.PrivateNetworkAccessInNoCORSModeOnly != want.PrivateNetworkAccessInNoCORSModeOnly {
		const tmpl = "PrivateNetworkAccessInNoCORSModeOnly: got %t; want %t"
		t.Errorf(tmpl, got.PrivateNetworkAccessInNoCORSModeOnly, want.PrivateNetworkAccessInNoCORSModeOnly)
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

func TestIncorrectConfig(t *testing.T) {
	type InvalidConfigTestCase struct {
		desc string
		cfg  *cors.Config
		msgs []string
	}
	var cases = []InvalidConfigTestCase{
		{
			desc: "no origin pattern specified",
			cfg:  &cors.Config{},
			msgs: []string{
				`cors: at least one origin must be allowed`,
			},
		}, {
			desc: "null origin",
			cfg: &cors.Config{
				Origins: []string{"null"},
			},
			msgs: []string{
				`cors: prohibited origin pattern "null"`,
			},
		}, {
			desc: "invalid origin pattern",
			cfg: &cors.Config{
				Origins: []string{"http://example.com:6060/path"},
			},
			msgs: []string{
				`cors: invalid origin pattern "http://example.com:6060/path"`,
			},
		}, {
			desc: "empty method name",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				Methods: []string{""},
			},
			msgs: []string{
				`cors: invalid method ""`,
			},
		}, {
			desc: "invalid method name",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				Methods: []string{"résumé"},
			},
			msgs: []string{
				`cors: invalid method "résumé"`,
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
			msgs: []string{
				`cors: forbidden method "CONNECT"`,
			},
		}, {
			desc: "empty request-header name",
			cfg: &cors.Config{
				Origins:        []string{"https://example.com"},
				RequestHeaders: []string{""},
			},
			msgs: []string{
				`cors: invalid request-header name ""`,
			},
		}, {
			desc: "invalid request-header name",
			cfg: &cors.Config{
				Origins:        []string{"https://example.com"},
				RequestHeaders: []string{"résumé"},
			},
			msgs: []string{
				`cors: invalid request-header name "résumé"`,
			},
		}, {
			desc: "forbidden request-header name",
			cfg: &cors.Config{
				Origins:        []string{"https://example.com"},
				RequestHeaders: []string{"Connection"},
			},
			msgs: []string{
				`cors: forbidden request-header name "Connection"`,
			},
		}, {
			desc: "forbidden request-header name with Sec- prefix",
			cfg: &cors.Config{
				Origins:        []string{"https://example.com"},
				RequestHeaders: []string{"Sec-Foo"},
			},
			msgs: []string{
				`cors: forbidden request-header name "Sec-Foo"`,
			},
		}, {
			desc: "forbidden request-header name with Proxy- prefix",
			cfg: &cors.Config{
				Origins:        []string{"https://example.com"},
				RequestHeaders: []string{"Proxy-Foo"},
			},
			msgs: []string{
				`cors: forbidden request-header name "Proxy-Foo"`,
			},
		}, {
			desc: "prohibited request-header name",
			cfg: &cors.Config{
				Origins:        []string{"https://example.com"},
				RequestHeaders: []string{"Access-Control-Allow-Origin"},
			},
			msgs: []string{
				`cors: prohibited request-header name "Access-Control-Allow-Origin"`,
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
			msgs: []string{
				`cors: out-of-bounds max-age value -2 (default: 5; max: 86400; disable caching: -1)`,
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
			msgs: []string{
				`cors: out-of-bounds max-age value 86401 (default: 5; max: 86400; disable caching: -1)`,
			},
		}, {
			desc: "empty response-header name",
			cfg: &cors.Config{
				Origins:         []string{"https://example.com"},
				ResponseHeaders: []string{""},
			},
			msgs: []string{
				`cors: invalid response-header name ""`,
			},
		}, {
			desc: "invalid response-header name",
			cfg: &cors.Config{
				Origins:         []string{"https://example.com"},
				ResponseHeaders: []string{"résumé"},
			},
			msgs: []string{
				`cors: invalid response-header name "résumé"`,
			},
		}, {
			desc: "forbidden response-header name",
			cfg: &cors.Config{
				Origins:         []string{"https://example.com"},
				ResponseHeaders: []string{"Set-Cookie"},
			},
			msgs: []string{
				`cors: forbidden response-header name "Set-Cookie"`,
			},
		}, {
			desc: "prohibited response-header name",
			cfg: &cors.Config{
				Origins:         []string{"https://example.com"},
				ResponseHeaders: []string{"Access-Control-Request-Method"},
			},
			msgs: []string{
				`cors: prohibited response-header name "Access-Control-Request-Method"`,
			},
		}, {
			desc: "preflight-success status less than 200",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 199,
				},
			},
			msgs: []string{
				`cors: out-of-bounds preflight-success status 199 (default: 204; min: 200; max: 299)`,
			},
		}, {
			desc: "preflight-success status greater than 299",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 300,
				},
			},
			msgs: []string{
				`cors: out-of-bounds preflight-success status 300 (default: 204; min: 200; max: 299)`,
			},
		}, {
			desc: "wildcard origin with Credentialed",
			cfg: &cors.Config{
				Origins:      []string{"*"},
				Credentialed: true,
			},
			msgs: []string{
				`cors: for security reasons, you cannot both allow all origins ` +
					`and enable credentialed access`,
			},
		}, {
			desc: "wildcard origin with PrivateNetworkAccess",
			cfg: &cors.Config{
				Origins: []string{"*"},
				ExtraConfig: cors.ExtraConfig{
					PrivateNetworkAccess: true,
				},
			},
			msgs: []string{
				`cors: for security reasons, you cannot both allow all origins ` +
					`and enable Private-Network Access`,
			},
		}, {
			desc: "wildcard origin with PrivateNetworkAccessInNoCORSModeOnly",
			cfg: &cors.Config{
				Origins: []string{"*"},
				ExtraConfig: cors.ExtraConfig{
					PrivateNetworkAccessInNoCORSModeOnly: true,
				},
			},
			msgs: []string{
				`cors: for security reasons, you cannot both allow all origins ` +
					`and enable Private-Network Access`,
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
			msgs: []string{
				`cors: for security reasons, insecure origin patterns like "http://example.com:6060" are by default prohibited when credentialed access is enabled`,
				`cors: for security reasons, insecure origin patterns like "http://*.example.com:6060" are by default prohibited when credentialed access is enabled`,
			},
		}, {
			desc: "insecure origin with PrivateNetworkAccess without DangerouslyTolerateInsecureOrigins",
			cfg: &cors.Config{
				Origins: []string{
					"http://example.com:6060",
					"http://*.example.com:6060",
				},
				ExtraConfig: cors.ExtraConfig{
					PrivateNetworkAccess: true,
				},
			},
			msgs: []string{
				`cors: for security reasons, insecure origin patterns like "http://example.com:6060" are by default prohibited when Private-Network Access is enabled`,
				`cors: for security reasons, insecure origin patterns like "http://*.example.com:6060" are by default prohibited when Private-Network Access is enabled`,
			},
		}, {
			desc: "insecure origin with PrivateNetworkAccessInNoCORSModeOnly without DangerouslyTolerateInsecureOrigins",
			cfg: &cors.Config{
				Origins: []string{
					"http://example.com:6060",
					"http://*.example.com:6060",
				},
				ExtraConfig: cors.ExtraConfig{
					PrivateNetworkAccessInNoCORSModeOnly: true,
				},
			},
			msgs: []string{
				`cors: for security reasons, insecure origin patterns like "http://example.com:6060" are by default prohibited when Private-Network Access is enabled`,
				`cors: for security reasons, insecure origin patterns like "http://*.example.com:6060" are by default prohibited when Private-Network Access is enabled`,
			},
		}, {
			desc: "insecure origin with Credentialed and PrivateNetworkAccess without DangerouslyTolerateInsecureOrigins",
			cfg: &cors.Config{
				Origins: []string{
					"http://example.com:6060",
					"http://*.example.com:6060",
				},
				Credentialed: true,
				ExtraConfig: cors.ExtraConfig{
					PrivateNetworkAccess: true,
				},
			},
			msgs: []string{
				`cors: for security reasons, insecure origin patterns like "http://example.com:6060" are by default prohibited when credentialed access is enabled`,
				`cors: for security reasons, insecure origin patterns like "http://example.com:6060" are by default prohibited when Private-Network Access is enabled`,
				`cors: for security reasons, insecure origin patterns like "http://*.example.com:6060" are by default prohibited when credentialed access is enabled`,
				`cors: for security reasons, insecure origin patterns like "http://*.example.com:6060" are by default prohibited when Private-Network Access is enabled`,
			},
		}, {
			desc: "insecure origin with Credentialed and PrivateNetworkAccessInNoCORSModeOnly without DangerouslyTolerateInsecureOrigins",
			cfg: &cors.Config{
				Origins: []string{
					"http://example.com:6060",
					"http://*.example.com:6060",
				},
				Credentialed: true,
				ExtraConfig: cors.ExtraConfig{
					PrivateNetworkAccessInNoCORSModeOnly: true,
				},
			},
			msgs: []string{
				`cors: for security reasons, insecure origin patterns like "http://example.com:6060" are by default prohibited when credentialed access is enabled`,
				`cors: for security reasons, insecure origin patterns like "http://example.com:6060" are by default prohibited when Private-Network Access is enabled`,
				`cors: for security reasons, insecure origin patterns like "http://*.example.com:6060" are by default prohibited when credentialed access is enabled`,
				`cors: for security reasons, insecure origin patterns like "http://*.example.com:6060" are by default prohibited when Private-Network Access is enabled`,
			},
		}, {
			desc: "wildcard pattern encompassing subdomains of a public suffix without DangerouslyTolerateSubdomainsOfPublicSuffixes",
			cfg: &cors.Config{
				Origins: []string{"https://*.com"},
			},
			msgs: []string{
				`cors: for security reasons, origin patterns like ` +
					`"https://*.com" that encompass subdomains of a ` +
					`public suffix are by default prohibited`,
			},
		}, {
			desc: "conjunct use of PrivateNetworkAccess and PrivateNetworkAccessInNoCORSModeOnly",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				ExtraConfig: cors.ExtraConfig{
					PrivateNetworkAccess:                 true,
					PrivateNetworkAccessInNoCORSModeOnly: true,
				},
			},
			msgs: []string{
				`cors: at most one form of Private-Network Access can be enabled`,
			},
		}, {
			desc: "wildcard response-header name with Credentialed",
			cfg: &cors.Config{
				Origins:         []string{"https://example.com"},
				Credentialed:    true,
				ResponseHeaders: []string{"*"},
			},
			msgs: []string{
				`cors: you cannot both expose all response headers and enable credentialed access`,
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
			msgs: []string{
				`cors: invalid origin pattern "https://example.com/"`,
				`cors: forbidden method "CONNECT"`,
				`cors: invalid method "résumé"`,
				`cors: invalid request-header name "résumé"`,
				`cors: prohibited request-header name "Access-Control-Allow-Origin"`,
				`cors: out-of-bounds max-age value 86401 (default: 5; max: 86400; disable caching: -1)`,
			},
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			mw, err := cors.NewMiddleware(*tc.cfg)
			if mw != nil {
				t.Error("got non-nil *Middleware; want nil *Middleware")
			}
			if err == nil {
				t.Error("got nil error; want non-nil error")
				return
			}
			var msgs []string
			for err := range allLeavesIn(err) {
				msgs = append(msgs, err.Error())
			}
			sort.Strings(msgs) // the order doesn't matter
			sort.Strings(tc.msgs)
			res, same := diff(msgs, tc.msgs)
			if !same {
				t.Error("unexpected error message(s):")
				for _, s := range res {
					t.Logf("\t%s", s)
				}
			}
		}
		t.Run(tc.desc, f)
	}
}

func allLeavesIn(err error) iter.Seq[error] {
	return func(yield func(error) bool) {
		switch err := err.(type) {
		// Note that there's no need for any "interface { Unwrap() error }" case
		// because nowhere do we "wrap" errors; we only ever "join" them.
		case interface{ Unwrap() []error }:
			for _, err := range err.Unwrap() {
				for err := range allLeavesIn(err) {
					if !yield(err) {
						return
					}
				}
			}
		default:
			if !yield(err) {
				return
			}
		}
	}
}

// diff reports whether x and y contain the same elements in the same order
// and returns a visual summary of the difference y-x.
func diff(x, y []string) (res []string, same bool) {
	same = len(x) == len(y)
	for 0 < len(x) && 0 < len(y) {
		if x[0] == y[0] {
			res = append(res, "  "+y[0])
			y = y[1:]
			x = x[1:]
			continue
		}
		same = false
		res = append(res, "- "+y[0]) // missing element
		y = y[1:]
	}
	for _, s := range x {
		res = append(res, "+ "+s) // extraneous element
	}
	return res, same
}
