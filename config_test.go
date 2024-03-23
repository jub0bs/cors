package cors_test

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
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
			for i := 0; i < typ.NumField(); i++ {
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
				`cors: at least one origin pattern must be specified`,
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
			desc: "wildcard origin in addition to other origin pattern",
			cfg: &cors.Config{
				Origins: []string{
					"*",
					"https://example.com",
				},
			},
			msgs: []string{
				`cors: specifying origin patterns in addition to * is prohibited`,
			},
		}, {
			desc: "origin pattern in addition to wildcard origin",
			cfg: &cors.Config{
				Origins: []string{
					"https://example.com",
					"*",
				},
			},
			msgs: []string{
				`cors: specifying origin patterns in addition to * is prohibited`,
			},
		}, {
			desc: "empty method name",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				Methods: []string{""},
			},
			msgs: []string{
				`cors: invalid method name ""`,
			},
		}, {
			desc: "invalid method name",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				Methods: []string{"résumé"},
			},
			msgs: []string{
				`cors: invalid method name "résumé"`,
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
				`cors: forbidden method name "CONNECT"`,
			},
		}, {
			desc: "wildcard in addition to other method",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				Methods: []string{
					"*",
					http.MethodGet,
				},
			},
			msgs: []string{
				`cors: specifying methods in addition to * is prohibited`,
			},
		}, {
			desc: "method in addition wildcard",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				Methods: []string{
					http.MethodGet,
					"*",
				},
			},
			msgs: []string{
				`cors: specifying methods in addition to * is prohibited`,
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
			desc: "wildcard in addition to request-header name other than Authorization",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				RequestHeaders: []string{
					"*",
					"Content-Type",
				},
			},
			msgs: []string{
				`cors: specifying request-header names (other than Authorization) in addition to * is prohibited`,
			},
		}, {
			desc: "request-header name other than Authorization in addition to wildcard",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				RequestHeaders: []string{
					"Content-Type",
					"*",
				},
			},
			msgs: []string{
				`cors: specifying request-header names (other than Authorization) in addition to * is prohibited`,
			},
		}, {
			desc: "wildcard and Authorization in addition to other request-header name",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				RequestHeaders: []string{
					"*",
					"Authorization",
					"Content-Type",
				},
			},
			msgs: []string{
				`cors: specifying request-header names (other than Authorization) in addition to * is prohibited`,
			},
		}, {
			desc: "request-header name other than Authorization in addition to Authorization and wildcard",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				RequestHeaders: []string{
					"Content-Type",
					"Authorization",
					"*",
				},
			},
			msgs: []string{
				`cors: specifying request-header names (other than Authorization) in addition to * is prohibited`,
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
				`cors: specified max-age value -2 is invalid`,
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
				`cors: specified max-age value 86401 exceeds upper bound 86400`,
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
			desc: "safelisted response-header name",
			cfg: &cors.Config{
				Origins:         []string{"https://example.com"},
				ResponseHeaders: []string{"Cache-Control"},
			},
			msgs: []string{
				`cors: response-header name "Cache-Control" needs not be explicitly exposed`,
			},
		}, {
			desc: "wildcard in addition to other response-header name",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				ResponseHeaders: []string{
					"*",
					"X-Response-Time",
				},
			},
			msgs: []string{
				`cors: specifying response-header names in addition to * is prohibited`,
			},
		}, {
			desc: "response-header name in addition to wildcard",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				ResponseHeaders: []string{
					"X-Response-Time",
					"*",
				},
			},
			msgs: []string{
				`cors: specifying response-header names in addition to * is prohibited`,
			},
		}, {
			desc: "preflight success status less than 200",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 199,
				},
			},
			msgs: []string{
				`cors: specified status 199 lies outside the 2xx range`,
			},
		}, {
			desc: "preflight success status greater than 299",
			cfg: &cors.Config{
				Origins: []string{"https://example.com"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 300,
				},
			},
			msgs: []string{
				`cors: specified status 300 lies outside the 2xx range`,
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
				`cors: for security reasons, insecure origin patterns like ` +
					`"http://example.com:6060" and "http://*.example.com:6060" ` +
					`are by default prohibited when credentialed access is enabled`,
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
				`cors: for security reasons, insecure origin patterns like ` +
					`"http://example.com:6060" and "http://*.example.com:6060" ` +
					`are by default prohibited when Private-Network Access is enabled`,
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
				`cors: for security reasons, insecure origin patterns like ` +
					`"http://example.com:6060" and "http://*.example.com:6060" ` +
					`are by default prohibited when Private-Network Access is enabled`,
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
				`cors: for security reasons, insecure origin patterns like ` +
					`"http://example.com:6060" and "http://*.example.com:6060" are ` +
					`by default prohibited when credentialed access is enabled ` +
					`and/or Private-Network Access is enabled`,
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
				`cors: for security reasons, insecure origin patterns like ` +
					`"http://example.com:6060" and "http://*.example.com:6060" are ` +
					`by default prohibited when credentialed access is enabled ` +
					`and/or Private-Network Access is enabled`,
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
				`cors: forbidden method name "CONNECT"`,
				`cors: invalid method name "résumé"`,
				`cors: invalid request-header name "résumé"`,
				`cors: prohibited request-header name "Access-Control-Allow-Origin"`,
				`cors: specified max-age value 86401 exceeds upper bound 86400`,
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
			msgs := flatten(err)
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

func flatten(err error) []string {
	return flattenRec(err, nil)
}

func flattenRec(err error, res []string) []string {
	type wrapper interface{ Unwrap() []error }
	errs, ok := err.(wrapper)
	if !ok {
		return append(res, err.Error())
	}
	for _, err := range errs.Unwrap() {
		res = flattenRec(err, res)
	}
	return res
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
