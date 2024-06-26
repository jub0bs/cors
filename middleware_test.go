package cors_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jub0bs/cors"
	"github.com/jub0bs/cors/internal/headers"
)

func TestMiddleware(t *testing.T) {
	cases := []MiddlewareTestCase{
		{
			desc:       "passthrough",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg:        nil,
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET",
					reqMethod: "GET",
				}, {
					desc:      "non-CORS OPTIONS",
					reqMethod: "OPTIONS",
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com/index.html",
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
				}, {
					desc:      "preflight with GET from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
					},
				}, {
					desc:      "preflight with PURGE from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PURGE",
					},
				}, {
					desc:      "preflight with PURGE and Content-Type from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PURGE",
						headerACRH:   "content-type",
					},
				}, {
					desc:      "preflight with GET from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   "GET",
					},
				}, {
					desc:      "preflight with GET from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com/index.html",
						headerACRM:   "GET",
					},
				}, {
					desc:      "preflight with PUT from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PUT",
					},
				}, {
					desc:      "preflight with PUT from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   "PUT",
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
				}, {
					desc:      "preflight with GET and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.org",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
				}, {
					desc:      "preflight with GET and ACRPN from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRPN:  "true",
						headerACRM:   "GET",
					},
				}, {
					desc:      "preflight with PUT and ACRPN headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRPN:  "true",
						headerACRM:   "PUT",
						headerACRH:   "bar,baz,foo",
					},
				}, {
					desc:      "preflight with GET and ACRPN from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRPN:  "true",
						headerACRM:   "GET",
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRPN:  "true",
						headerACRM:   "PUT",
						headerACRH:   "bar,baz,foo",
					},
				},
			},
		}, {
			desc:       "credentialed",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{"http://localhost:9090"},
				Credentialed:    true,
				Methods:         []string{"GET", "POST", "PURGE", "HELP"},
				RequestHeaders:  []string{"Authorization"},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{"X-Foo", "X-Bar"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 279,
				},
			},
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET",
					reqMethod: "GET",
					respHeaders: Headers{
						headerVary: headerOrigin,
					},
				}, {
					desc:      "non-CORS OPTIONS",
					reqMethod: "OPTIONS",
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
					},
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerACAC: "true",
						headerACEH: "x-bar,x-foo",
						headerVary: headerOrigin,
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
					respHeaders: Headers{
						headerVary: headerOrigin,
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com/index.html",
					},
					respHeaders: Headers{
						headerVary: headerOrigin,
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
					},
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerACAC: "true",
						headerACEH: "x-bar,x-foo",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerACAC: "true",
						headerACMA: "30",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PURGE from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PURGE",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerACAC: "true",
						headerACAM: "PURGE",
						headerACMA: "30",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PURGE and Content-Type from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PURGE",
						headerACRH:   "content-type",
					},
					preflight:                true,
					preflightPassesCORSCheck: false,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   "GET",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com/index.html",
						headerACRM:   "GET",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PUT",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   "PUT",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.org",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and ACRPN from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRPN:  "true",
						headerACRM:   "GET",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT and ACRPN headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRPN:  "true",
						headerACRM:   "PUT",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and ACRPN from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRPN:  "true",
						headerACRM:   "GET",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRPN:  "true",
						headerACRM:   "PUT",
						headerACRH:   "bar,baz,foo",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "credentialed all req headers",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{"http://localhost:9090"},
				Credentialed:    true,
				RequestHeaders:  []string{"*"},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{"X-Foo", "X-Bar"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 279,
				},
			},
			cases: []ReqTestCase{
				{
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerACAC: "true",
						headerACAH: "bar,baz,foo",
						headerACMA: "30",
						headerVary: varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "no preflight caching",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{"http://localhost:9090"},
				Credentialed:    true,
				RequestHeaders:  []string{"*"},
				MaxAgeInSeconds: -1,
				ResponseHeaders: []string{"X-Foo", "X-Bar"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 279,
				},
			},
			cases: []ReqTestCase{
				{
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerACAC: "true",
						headerACAH: "bar,baz,foo",
						headerACMA: "0",
						headerVary: varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "PNA",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{"http://localhost:9090"},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{"X-Foo", "X-Bar"},
				ExtraConfig: cors.ExtraConfig{
					PrivateNetworkAccess:   true,
					PreflightSuccessStatus: 279,
				},
			},
			cases: []ReqTestCase{
				{
					desc:      "preflight with ACRPN",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRPN:  "true",
						headerACRM:   "GET",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO:  "http://localhost:9090",
						headerACAPN: "true",
						headerACMA:  "30",
						headerVary:  varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "PNAnoCORS",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{"http://localhost:9090"},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{"X-Foo", "X-Bar"},
				ExtraConfig: cors.ExtraConfig{
					PrivateNetworkAccessInNoCORSModeOnly: true,
					PreflightSuccessStatus:               279,
				},
			},
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET",
					reqMethod: "GET",
				}, {
					desc:      "non-CORS OPTIONS",
					reqMethod: "OPTIONS",
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
					},
				}, {
					desc:      "actual OPTIONS",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
					},
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with ACRPN",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRPN:  "true",
						headerACRM:   "GET",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO:  "http://localhost:9090",
						headerACAPN: "true",
						headerACMA:  "30",
						headerVary:  varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "credentialed no req headers",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{"http://localhost:9090"},
				Credentialed:    true,
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{"X-Foo", "X-Bar"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 279,
				},
			},
			cases: []ReqTestCase{
				{
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "debug credentialed no req headers",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{"http://localhost:9090"},
				Credentialed:    true,
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{"X-Foo", "X-Bar"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 279,
				},
			},
			debug: true,
			cases: []ReqTestCase{
				{
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerACAC: "true",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with disallowed method",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PUT",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerACAC: "true",
						headerVary: varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "debug credentialed some req headers",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{"http://localhost:9090"},
				Credentialed:    true,
				RequestHeaders:  []string{"Authorization"},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{"X-Foo", "X-Bar"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 279,
				},
			},
			debug: true,
			cases: []ReqTestCase{
				{
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerACAC: "true",
						headerACAH: "authorization",
						headerACMA: "30",
						headerVary: varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "all req headers other than Authorization",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{wildcard},
				Methods:         []string{wildcard},
				RequestHeaders:  []string{wildcard},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{wildcard},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 279,
				},
			},
			debug: true,
			cases: []ReqTestCase{
				{
					desc:      "preflight with PURGE and Content-Type",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PURGE",
						headerACRH:   "content-type",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: wildcard,
						headerACAM: wildcard,
						headerACAH: wildcard,
						headerACMA: "30",
						headerVary: varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "debug allow all",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{wildcard},
				Methods:         []string{wildcard},
				RequestHeaders:  []string{"Authorization", wildcard},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{wildcard},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 279,
				},
			},
			debug: true,
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET request",
					reqMethod: "GET",
					respHeaders: Headers{
						headerACAO: wildcard,
						headerACEH: wildcard,
					},
				}, {
					desc:      "non-CORS OPTIONS request",
					reqMethod: "OPTIONS",
					respHeaders: Headers{
						headerACAO: wildcard,
						headerACEH: wildcard,
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "actual GET request",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
					},
					respHeaders: Headers{
						headerACAO: wildcard,
						headerACEH: wildcard,
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com/index.html",
					},
					respHeaders: Headers{
						headerACAO: wildcard,
						headerACEH: wildcard,
					},
				}, {
					desc:      "actual OPTIONS request",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
					},
					respHeaders: Headers{
						headerACAO: wildcard,
						headerACEH: wildcard,
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: wildcard,
						headerACMA: "30",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PURGE",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PURGE",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: wildcard,
						headerACAM: wildcard,
						headerACMA: "30",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and Content-Type",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PURGE",
						headerACRH:   "content-type",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: wildcard,
						headerACAM: wildcard,
						headerACAH: wildcardAndAuth,
						headerACMA: "30",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com/index.html",
						headerACRM:   "GET",
					},
					preflight:      true,
					preflightFails: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PUT",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: wildcard,
						headerACAM: wildcard,
						headerACMA: "30",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and headers",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: wildcard,
						headerACAH: wildcardAndAuth,
						headerACMA: "30",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and ACRPN",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRPN:  "true",
						headerACRM:   "GET",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerACAO: wildcard,
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRPN:  "true",
						headerACRM:   "PUT",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerACAO: wildcard,
						headerVary: varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "credentialed allow some",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins: []string{
					"https://example.com:8080",
					"https://*.example.com",
				},
				Credentialed: true,
				Methods: []string{
					"GET",
					http.MethodPost,
					"PUT",
					http.MethodDelete,
				},
				RequestHeaders: []string{
					"Foo",
					"Bar",
					"Baz",
					"Qux",
					"Quux",
				},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{
					"X-Foo",
					"X-Bar",
				},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 279,
				},
			},
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET request",
					reqMethod: "GET",
					respHeaders: Headers{
						headerVary: headers.Origin,
					},
				}, {
					desc:      "non-CORS OPTIONS request",
					reqMethod: "OPTIONS",
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com:8080",
					},
					respHeaders: Headers{
						headerACAO: "https://example.com:8080",
						headerACAC: "true",
						headerACEH: "x-bar,x-foo",
						headerVary: headerOrigin,
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com:6060",
					},
					respHeaders: Headers{
						headerVary: headerOrigin,
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com/index.html",
					},
					respHeaders: Headers{
						headerVary: headerOrigin,
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com:8080",
					},
					respHeaders: Headers{
						headerACAO: "https://example.com:8080",
						headerACAC: "true",
						headerACEH: "x-bar,x-foo",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://foo.example.com:8080",
					},
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com:8080",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: "https://example.com:8080",
						headerACAC: "true",
						headerACAH: "bar,baz,foo",
						headerACMA: "30",
						headerVary: varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "outer Vary middleware",
			outerMw:    &varyMiddleware,
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins: []string{"http://localhost:9090"},
			},
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET",
					reqMethod: "GET",
					respHeaders: Headers{
						headerVary: headerOrigin,
					},
				}, {
					desc:      "non-CORS OPTIONS",
					reqMethod: "OPTIONS",
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
					},
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerVary: headerOrigin,
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
					respHeaders: Headers{
						headerVary: headerOrigin,
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com/index.html",
					},
					respHeaders: Headers{
						headerVary: headerOrigin,
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
					},
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PURGE from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PURGE",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PURGE and Content-Type from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PURGE",
						headerACRH:   "content-type",
					},
					preflight:                true,
					preflightPassesCORSCheck: false,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   "GET",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com/index.html",
						headerACRM:   "GET",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PUT",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   "PUT",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.org",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and ACRPN from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRPN:  "true",
						headerACRM:   "GET",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT and ACRPN headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRPN:  "true",
						headerACRM:   "PUT",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and ACRPN from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRPN:  "true",
						headerACRM:   "GET",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRPN:  "true",
						headerACRM:   "PUT",
						headerACRH:   "bar,baz,foo",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "regression tests for GHSA-vhxv-fg4m-p2w8",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins: []string{
					"https://foo.com",
					"https://bar.com",
				},
			},
			cases: []ReqTestCase{
				{
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://barfoo.com",
					},
					respHeaders: Headers{
						headerVary: headerOrigin,
					},
				}, {
					desc:      "actual GET from disallowed 2",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://foobar.com",
					},
					respHeaders: Headers{
						headerVary: headerOrigin,
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://barfoo.com",
					},
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "actual OPTIONS from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://foobar.com",
					},
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://barfoo.com",
						headerACRM:   "GET",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://foobar.com",
						headerACRM:   "GET",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://barfoo.com",
						headerACRM:   "PUT",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://foobar.com",
						headerACRM:   "PUT",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://barfoo.com",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and headers from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://foobar.com",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and ACRPN from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://barfoo.com",
						headerACRPN:  "true",
						headerACRM:   "GET",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with GET and ACRPN from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://foobar.com",
						headerACRPN:  "true",
						headerACRM:   "GET",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://barfoo.com",
						headerACRPN:  "true",
						headerACRM:   "PUT",
						headerACRH:   "bar,baz,foo",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://foobar.com",
						headerACRPN:  "true",
						headerACRM:   "PUT",
						headerACRH:   "bar,baz,foo",
					},
					preflight: true,
					respHeaders: Headers{
						headerVary: varyPreflightValue,
					},
				},
			},
		},
	}
	for _, mwtc := range cases {
		f := func(t *testing.T) {
			t.Parallel()
			var (
				mw  *cors.Middleware
				err error
			)
			if mwtc.cfg == nil {
				mw = new(cors.Middleware)
			} else {
				mw, err = cors.NewMiddleware(*mwtc.cfg)
				if err != nil {
					t.Fatalf("failure to build CORS middleware: %v", err)
				}
			}
			if mwtc.debug {
				mw.SetDebug(true)
			}
			for _, tc := range mwtc.cases {
				f := func(t *testing.T) {
					// --- arrange ---
					innerHandler := mwtc.newHandler()
					handler := mw.Wrap(innerHandler)
					if outerMiddleware := mwtc.outerMw; outerMiddleware != nil {
						handler = outerMiddleware.Wrap(handler)
					}
					req := newRequest(tc.reqMethod, tc.reqHeaders)
					rec := httptest.NewRecorder()

					// --- act ---
					handler.ServeHTTP(rec, req)
					res := rec.Result()

					// --- assert ---
					spy, ok := innerHandler.(*spyHandler)
					if !ok {
						t.Fatalf("handler is not a *spyHandler")
					}
					if tc.preflight { // preflight request
						if spy.called.Load() {
							t.Error("wrapped handler was called, but it should not have been")
						}
						assertPreflightStatus(t, spy.statusCode, res.StatusCode, &mwtc, &tc)
						assertResponseHeaders(t, res.Header, tc.respHeaders)
						if mwtc.outerMw != nil {
							assertResponseHeaders(t, res.Header, mwtc.outerMw.hdrs)
						}
						assertNoMoreResponseHeaders(t, res.Header)
						assertBody(t, res.Body, "")
						return
					} // non-preflight request
					if !spy.called.Load() {
						t.Error("wrapped handler wasn't called, but it should have been")
					}
					if res.StatusCode != spy.statusCode {
						const tmpl = "got status code %d; want %d"
						t.Errorf(tmpl, res.StatusCode, spy.statusCode)
					}
					assertResponseHeaders(t, res.Header, spy.respHeaders)
					assertResponseHeaders(t, res.Header, tc.respHeaders)
					if mwtc.outerMw != nil {
						assertResponseHeaders(t, res.Header, mwtc.outerMw.hdrs)
					}
					assertNoMoreResponseHeaders(t, res.Header)
					assertBody(t, res.Body, spy.body)
				}
				t.Run(tc.desc, f)
			}
		}
		t.Run(mwtc.desc, f)
	}
}

func TestWrappedHandlerCannotMutatePackageLevelSlices(t *testing.T) {
	cases := []MiddlewareTestCase{
		{
			desc:       "anonymous",
			newHandler: newMutatingHandler,
			cfg: &cors.Config{
				Origins:         []string{"*"},
				ResponseHeaders: []string{"*"},
			},
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET",
					reqMethod: "GET",
				}, {
					desc:      "actual GET",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
				}, {
					desc:      "actual OPTIONS",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
				},
			},
		}, {
			desc:       "credentialed",
			newHandler: newMutatingHandler,
			cfg: &cors.Config{
				Origins:         []string{"https://example.com"},
				Credentialed:    true,
				ResponseHeaders: []string{"X-Foo", "X-Bar"},
			},
			cases: []ReqTestCase{
				{
					desc:      "actual GET",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
				}, {
					desc:      "actual OPTIONS",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
				},
			},
		},
	}
	checks := []struct {
		desc string
		old  string
		sgl  []string
	}{
		{
			desc: "headers.PreflightVarySgl[0]",
			old:  headers.PreflightVarySgl[0],
			sgl:  headers.PreflightVarySgl,
		}, {
			desc: "headers.TrueSgl[0]",
			old:  headers.TrueSgl[0],
			sgl:  headers.TrueSgl,
		}, {
			desc: "headers.OriginSgl[0]",
			old:  headers.OriginSgl[0],
			sgl:  headers.OriginSgl,
		}, {
			desc: "headers.WildcardSgl[0]",
			old:  headers.WildcardSgl[0],
			sgl:  headers.WildcardSgl,
		}, {
			desc: "headers.WildcardAuthSgl[0]",
			old:  headers.WildcardAuthSgl[0],
			sgl:  headers.WildcardAuthSgl,
		},
	}
	for _, mwtc := range cases {
		f := func(t *testing.T) {
			t.Parallel()
			var (
				mw  *cors.Middleware
				err error
			)
			if mwtc.cfg == nil {
				mw = new(cors.Middleware)
			} else {
				mw, err = cors.NewMiddleware(*mwtc.cfg)
				if err != nil {
					t.Fatalf("failure to build CORS middleware: %v", err)
				}
			}
			for _, tc := range mwtc.cases {
				f := func(t *testing.T) {
					// --- arrange ---
					handler := mwtc.newHandler()
					handler = mw.Wrap(handler)
					req := newRequest(tc.reqMethod, tc.reqHeaders)
					rec := httptest.NewRecorder()

					// --- act ---
					handler.ServeHTTP(rec, req)

					// --- assert ---
					for _, check := range checks {
						want := check.old
						got := check.sgl[0]
						if got != want {
							t.Errorf("%s: got %q; want %q", check.desc, got, want)
						}
					}
				}
				t.Run(tc.desc, f)
			}
		}
		t.Run(mwtc.desc, f)
	}
}

func TestReconfigure(t *testing.T) {
	cases := []MiddlewareTestCase{
		{
			desc:       "passthrough",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg:        nil,
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET",
					reqMethod: "GET",
				}, {
					desc:      "non-CORS OPTIONS",
					reqMethod: "OPTIONS",
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: Headers{
						headerOrigin: "https://example.com/index.html",
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
					},
				}, {
					desc:      "preflight with GET from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
					},
				}, {
					desc:      "preflight with PURGE from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PURGE",
					},
				}, {
					desc:      "preflight with PURGE and Content-Type from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PURGE",
						headerACRH:   "content-type",
					},
				}, {
					desc:      "preflight with GET from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   "GET",
					},
				}, {
					desc:      "preflight with GET from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com/index.html",
						headerACRM:   "GET",
					},
				}, {
					desc:      "preflight with PUT from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PUT",
					},
				}, {
					desc:      "preflight with PUT from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRM:   "PUT",
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
				}, {
					desc:      "preflight with GET and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.org",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
				}, {
					desc:      "preflight with GET and ACRPN from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRPN:  "true",
						headerACRM:   "GET",
					},
				}, {
					desc:      "preflight with PUT and ACRPN headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRPN:  "true",
						headerACRM:   "PUT",
						headerACRH:   "bar,baz,foo",
					},
				}, {
					desc:      "preflight with GET and ACRPN from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRPN:  "true",
						headerACRM:   "GET",
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "https://example.com",
						headerACRPN:  "true",
						headerACRM:   "PUT",
						headerACRH:   "bar,baz,foo",
					},
				},
			},
		}, {
			desc:       "debug credentialed no req headers",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{"http://localhost:9090"},
				Credentialed:    true,
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{"X-Foo", "X-Bar"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 279,
				},
			},
			debug: true, // to check whether the debug mode will be retained after reconfiguration
			cases: []ReqTestCase{
				{
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerACAC: "true",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with disallowed method",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PUT",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerACAC: "true",
						headerVary: varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "credentialed all req headers",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{"http://localhost:9090"},
				Credentialed:    true,
				RequestHeaders:  []string{"*"},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{"X-Foo", "X-Bar"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 279,
				},
			},
			debug: false, // to check whether the previous debug mode was retained after reconfiguration
			cases: []ReqTestCase{
				{
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerACAC: "true",
						headerACAH: "bar,baz,foo",
						headerACMA: "30",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PURGE and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PURGE",
						headerACRH:   "bar,baz,foo,qux",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           false, // would be true if debug were false
					respHeaders: Headers{
						headerACAO: "http://localhost:9090", // would be absent if debug were false
						headerACAC: "true",                  // would be absent if debug were false
						headerVary: varyPreflightValue,
					},
				},
			},
		}, {
			desc:       "invalid config",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg:        new(cors.Config), // invalid: no origin patterns specified
			invalid:    true,
		}, {
			desc:       "credentialed all req headers",
			newHandler: newSpyHandler(200, Headers{headerVary: "foo"}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{"http://localhost:9090"},
				Credentialed:    true,
				RequestHeaders:  []string{"*"},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{"X-Foo", "X-Bar"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus: 279,
				},
			},
			debug: false, // to check whether the previous debug mode was retained
			cases: []ReqTestCase{
				{
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "GET",
						headerACRH:   "bar,baz,foo",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: Headers{
						headerACAO: "http://localhost:9090",
						headerACAC: "true",
						headerACAH: "bar,baz,foo",
						headerACMA: "30",
						headerVary: varyPreflightValue,
					},
				}, {
					desc:      "preflight with PURGE and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: Headers{
						headerOrigin: "http://localhost:9090",
						headerACRM:   "PURGE",
						headerACRH:   "bar,baz,foo,qux",
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           false, // would be true if debug were false
					respHeaders: Headers{
						headerACAO: "http://localhost:9090", // would be absent if debug were false
						headerACAC: "true",                  // would be absent if debug were false
						headerVary: varyPreflightValue,
					},
				},
			},
		},
	}
	var mw cors.Middleware
	for _, mwtc := range cases {
		err := mw.Reconfigure(mwtc.cfg)
		if err != nil && !mwtc.invalid {
			t.Fatalf("failure to reconfigure CORS middleware: %v", err)
		}
		if err == nil && mwtc.invalid {
			t.Fatal("unexpected absence of failure to reconfigure CORS middleware")
		}
		if mwtc.debug {
			mw.SetDebug(true)
		}
		for _, tc := range mwtc.cases {
			f := func(t *testing.T) {
				// --- arrange ---
				innerHandler := mwtc.newHandler()
				handler := mw.Wrap(innerHandler)
				if outerMiddleware := mwtc.outerMw; outerMiddleware != nil {
					handler = outerMiddleware.Wrap(handler)
				}
				req := newRequest(tc.reqMethod, tc.reqHeaders)
				rec := httptest.NewRecorder()

				// --- act ---
				handler.ServeHTTP(rec, req)
				res := rec.Result()

				// --- assert ---
				spy, ok := innerHandler.(*spyHandler)
				if !ok {
					t.Fatalf("handler is not a *spyHandler")
				}
				if tc.preflight { // preflight request
					if spy.called.Load() {
						t.Error("wrapped handler was called, but it should not have been")
					}
					assertPreflightStatus(t, spy.statusCode, res.StatusCode, &mwtc, &tc)
					assertResponseHeaders(t, res.Header, tc.respHeaders)
					if mwtc.outerMw != nil {
						assertResponseHeaders(t, res.Header, mwtc.outerMw.hdrs)
					}
					assertNoMoreResponseHeaders(t, res.Header)
					assertBody(t, res.Body, "")
					return
				} // non-preflight request
				if !spy.called.Load() {
					t.Error("wrapped handler wasn't called, but it should have been")
				}
				if res.StatusCode != spy.statusCode {
					const tmpl = "got status code %d; want %d"
					t.Errorf(tmpl, res.StatusCode, spy.statusCode)
				}
				assertResponseHeaders(t, res.Header, spy.respHeaders)
				assertResponseHeaders(t, res.Header, tc.respHeaders)
				if mwtc.outerMw != nil {
					assertResponseHeaders(t, res.Header, mwtc.outerMw.hdrs)
				}
				assertNoMoreResponseHeaders(t, res.Header)
				assertBody(t, res.Body, spy.body)
			}
			t.Run(tc.desc, f)
		}
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
				RequestHeaders:  []string{"*", "Authorization"},
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
				RequestHeaders:  []string{"Authorization", "X-Bar", "X-Foo"},
				MaxAgeInSeconds: -1,
				ResponseHeaders: []string{"X-Bar", "X-Foo"},
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
				ResponseHeaders: []string{"X-Bar", "X-Foo"},
				ExtraConfig: cors.ExtraConfig{
					PreflightSuccessStatus:             279,
					PrivateNetworkAccess:               true,
					DangerouslyTolerateInsecureOrigins: true,
				},
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
