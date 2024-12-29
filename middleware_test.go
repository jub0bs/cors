package cors_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jub0bs/cors"
	"github.com/jub0bs/cors/internal/headers"
)

func TestMiddleware(t *testing.T) {
	cases := []MiddlewareTestCase{
		{
			desc:       "passthrough",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com/index.html"},
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				}, {
					desc:      "preflight with GET from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
					},
				}, {
					desc:      "preflight with PURGE from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
					},
				}, {
					desc:      "preflight with PURGE and Content-Type from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"content-type"},
					},
				}, {
					desc:      "preflight with GET from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"GET"},
					},
				}, {
					desc:      "preflight with GET from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com/index.html"},
						headerACRM:   {"GET"},
					},
				}, {
					desc:      "preflight with PUT from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PUT"},
					},
				}, {
					desc:      "preflight with PUT from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"PUT"},
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
				}, {
					desc:      "preflight with GET and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.org"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
				}, {
					desc:      "preflight with GET and ACRPN from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRPN:  {"true"},
						headerACRM:   {"GET"},
					},
				}, {
					desc:      "preflight with PUT and ACRPN headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRPN:  {"true"},
						headerACRM:   {"PUT"},
						headerACRH:   {"bar,baz,foo"},
					},
				}, {
					desc:      "preflight with GET and ACRPN from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRPN:  {"true"},
						headerACRM:   {"GET"},
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRPN:  {"true"},
						headerACRM:   {"PUT"},
						headerACRH:   {"bar,baz,foo"},
					},
				},
			},
		}, {
			desc:       "credentialed",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					respHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "non-CORS OPTIONS",
					reqMethod: "OPTIONS",
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACEH: {"x-bar,x-foo"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
					respHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com/index.html"},
					},
					respHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACEH: {"x-bar,x-foo"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PURGE from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAM: {"PURGE"},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PURGE and Content-Type from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"content-type"},
					},
					preflight:                true,
					preflightPassesCORSCheck: false,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PURGE and Authorization from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"authorization"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAM: {"PURGE"},
						headerACAH: {"authorization"},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PURGE and Authorization with some empty elements from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {",,authorization,,"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAM: {"PURGE"},
						headerACAH: {",,authorization,,"},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PURGE and Authorization with too many empty elements from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"authorization" + strings.Repeat(",", 17)},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PURGE and Authorization with some empty ACRH field lines from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   append(make([]string, 16), "authorization"),
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAM: {"PURGE"},
						headerACAH: append(make([]string, 16), "authorization"),
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PURGE and Authorization with too many empty ACRH field lines from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   append(make([]string, 17), "authorization"),
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"GET"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com/index.html"},
						headerACRM:   {"GET"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PUT"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"PUT"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.org"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and ACRPN from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRPN:  {"true"},
						headerACRM:   {"GET"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT and ACRPN headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRPN:  {"true"},
						headerACRM:   {"PUT"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and ACRPN from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRPN:  {"true"},
						headerACRM:   {"GET"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRPN:  {"true"},
						headerACRM:   {"PUT"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "credentialed all req headers",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar,baz,foo"},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers with some OWS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar , baz\t, foo\t"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar , baz\t, foo\t"},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers with too much OWS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar \t, baz\t, foo\t"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar \t, baz\t, foo\t"},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers with some empty elements from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo" + strings.Repeat(",", 16)},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar,baz,foo" + strings.Repeat(",", 16)},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers with too many empty elements from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo" + strings.Repeat(",", 17)},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar,baz,foo" + strings.Repeat(",", 17)},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers with some empty ACHR field lines from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   append(make([]string, 16), "bar,baz,foo"),
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: append(make([]string, 16), "bar,baz,foo"),
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers with too many empty ACHR field lines from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   append(make([]string, 17), "bar,baz,foo"),
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: append(make([]string, 17), "bar,baz,foo"),
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "PNA",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRPN:  {"true"},
						headerACRM:   {"GET"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO:  {"http://localhost:9090"},
						headerACAPN: {"true"},
						headerACMA:  {"30"},
						headerVary:  {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "PNAnoCORS",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
				}, {
					desc:      "actual OPTIONS",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with ACRPN",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRPN:  {"true"},
						headerACRM:   {"GET"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO:  {"http://localhost:9090"},
						headerACAPN: {"true"},
						headerACMA:  {"30"},
						headerVary:  {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "credentialed no req headers",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "debug credentialed no req headers",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with disallowed method",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PUT"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerVary: {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "debug credentialed some req headers",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"authorization"},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "all req headers other than Authorization",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"content-type"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {wildcard},
						headerACAM: {wildcard},
						headerACAH: {wildcard},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "debug allow all",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					respHeaders: http.Header{
						headerACAO: {wildcard},
						headerACEH: {wildcard},
					},
				}, {
					desc:      "non-CORS OPTIONS request",
					reqMethod: "OPTIONS",
					respHeaders: http.Header{
						headerACAO: {wildcard},
						headerACEH: {wildcard},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "actual GET request",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
					respHeaders: http.Header{
						headerACAO: {wildcard},
						headerACEH: {wildcard},
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com/index.html"},
					},
					respHeaders: http.Header{
						headerACAO: {wildcard},
						headerACEH: {wildcard},
					},
				}, {
					desc:      "actual OPTIONS request",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
					respHeaders: http.Header{
						headerACAO: {wildcard},
						headerACEH: {wildcard},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {wildcard},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PURGE",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {wildcard},
						headerACAM: {wildcard},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PURGE and Content-Type",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"content-type"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {wildcard},
						headerACAM: {wildcard},
						headerACAH: {wildcardAndAuth},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com/index.html"},
						headerACRM:   {"GET"},
					},
					preflight:      true,
					preflightFails: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PUT"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {wildcard},
						headerACAM: {wildcard},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {wildcard},
						headerACAH: {wildcardAndAuth},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and ACRPN",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRPN:  {"true"},
						headerACRM:   {"GET"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerACAO: {wildcard},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRPN:  {"true"},
						headerACRM:   {"PUT"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerACAO: {wildcard},
						headerVary: {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "credentialed allow some",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					respHeaders: http.Header{
						headerVary: {headers.Origin},
					},
				}, {
					desc:      "non-CORS OPTIONS request",
					reqMethod: "OPTIONS",
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com:8080"},
					},
					respHeaders: http.Header{
						headerACAO: {"https://example.com:8080"},
						headerACAC: {"true"},
						headerACEH: {"x-bar,x-foo"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com:6060"},
					},
					respHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com/index.html"},
					},
					respHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com:8080"},
					},
					respHeaders: http.Header{
						headerACAO: {"https://example.com:8080"},
						headerACAC: {"true"},
						headerACEH: {"x-bar,x-foo"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://foo.example.com:8080"},
					},
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com:8080"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"https://example.com:8080"},
						headerACAC: {"true"},
						headerACAH: {"bar,baz,foo"},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "outer Vary middleware",
			outerMw:    &varyMiddleware,
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
			cfg: &cors.Config{
				Origins: []string{"http://localhost:9090"},
			},
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET",
					reqMethod: "GET",
					respHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "non-CORS OPTIONS",
					reqMethod: "OPTIONS",
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
					respHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com/index.html"},
					},
					respHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PURGE from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PURGE and Content-Type from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"content-type"},
					},
					preflight:                true,
					preflightPassesCORSCheck: false,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"GET"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com/index.html"},
						headerACRM:   {"GET"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PUT"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"PUT"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.org"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and ACRPN from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRPN:  {"true"},
						headerACRM:   {"GET"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT and ACRPN headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRPN:  {"true"},
						headerACRM:   {"PUT"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and ACRPN from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRPN:  {"true"},
						headerACRM:   {"GET"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRPN:  {"true"},
						headerACRM:   {"PUT"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "regression tests for GHSA-vhxv-fg4m-p2w8",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					reqHeaders: http.Header{
						headerOrigin: {"https://barfoo.com"},
					},
					respHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from disallowed 2",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://foobar.com"},
					},
					respHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://barfoo.com"},
					},
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "actual OPTIONS from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://foobar.com"},
					},
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://barfoo.com"},
						headerACRM:   {"GET"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://foobar.com"},
						headerACRM:   {"GET"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://barfoo.com"},
						headerACRM:   {"PUT"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://foobar.com"},
						headerACRM:   {"PUT"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://barfoo.com"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://foobar.com"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and ACRPN from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://barfoo.com"},
						headerACRPN:  {"true"},
						headerACRM:   {"GET"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and ACRPN from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://foobar.com"},
						headerACRPN:  {"true"},
						headerACRM:   {"GET"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://barfoo.com"},
						headerACRPN:  {"true"},
						headerACRM:   {"PUT"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://foobar.com"},
						headerACRPN:  {"true"},
						headerACRM:   {"PUT"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight: true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "insecure origin with non-HTTP scheme",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
			cfg: &cors.Config{
				Origins: []string{
					"connector://example.com",
				},
				Credentialed: true,
				ExtraConfig: cors.ExtraConfig{
					DangerouslyTolerateInsecureOrigins: true,
				},
			},
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET request",
					reqMethod: "GET",
					respHeaders: http.Header{
						headerVary: {headers.Origin},
					},
				}, {
					desc:      "non-CORS OPTIONS request",
					reqMethod: "OPTIONS",
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"connector://example.com"},
					},
					respHeaders: http.Header{
						headerACAO: {"connector://example.com"},
						headerACAC: {"true"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"connector://example.com:6060"},
					},
					respHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"connector://example.com/index.html"},
					},
					respHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"connector://example.com"},
					},
					respHeaders: http.Header{
						headerACAO: {"connector://example.com"},
						headerACAC: {"true"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"connector://example.com:8080"},
					},
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"connector://example.com"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "arbitrary subdomains of depth one or more and arbitrary ports",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
			cfg: &cors.Config{
				Origins: []string{"http://*.example.com:*"},
			},
			cases: []ReqTestCase{
				{
					desc:      "actual GET from subdomain",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://foo.example.com"},
					},
					respHeaders: http.Header{
						headerACAO: {"http://foo.example.com"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from subdomain and port",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://foo.example.com:6060"},
					},
					respHeaders: http.Header{
						headerACAO: {"http://foo.example.com:6060"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from deeper ssubdomain",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://bar.foo.example.com"},
					},
					respHeaders: http.Header{
						headerACAO: {"http://bar.foo.example.com"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from deeper ssubdomain and port",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://bar.foo.example.com:8080"},
					},
					respHeaders: http.Header{
						headerACAO: {"http://bar.foo.example.com:8080"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://example.com"},
					},
					respHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://foo.example.com"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerVary: {varyPreflightValue},
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
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				}, {
					desc:      "actual OPTIONS",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
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
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				}, {
					desc:      "actual OPTIONS",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
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
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com/index.html"},
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				}, {
					desc:      "preflight with GET from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
					},
				}, {
					desc:      "preflight with PURGE from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
					},
				}, {
					desc:      "preflight with PURGE and Content-Type from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"content-type"},
					},
				}, {
					desc:      "preflight with GET from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"GET"},
					},
				}, {
					desc:      "preflight with GET from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com/index.html"},
						headerACRM:   {"GET"},
					},
				}, {
					desc:      "preflight with PUT from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PUT"},
					},
				}, {
					desc:      "preflight with PUT from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"PUT"},
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
				}, {
					desc:      "preflight with GET and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.org"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
				}, {
					desc:      "preflight with GET and ACRPN from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRPN:  {"true"},
						headerACRM:   {"GET"},
					},
				}, {
					desc:      "preflight with PUT and ACRPN headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRPN:  {"true"},
						headerACRM:   {"PUT"},
						headerACRH:   {"bar,baz,foo"},
					},
				}, {
					desc:      "preflight with GET and ACRPN from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRPN:  {"true"},
						headerACRM:   {"GET"},
					},
				}, {
					desc:      "preflight with PUT and ACRPN and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRPN:  {"true"},
						headerACRM:   {"PUT"},
						headerACRH:   {"bar,baz,foo"},
					},
				},
			},
		}, {
			desc:       "debug credentialed no req headers",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with disallowed method",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PUT"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerVary: {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "credentialed all req headers",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar,baz,foo"},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PURGE and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"bar,baz,foo,qux"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           false, // would be true if debug were false
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"}, // would be absent if debug were false
						headerACAC: {"true"},                  // would be absent if debug were false
						headerVary: {varyPreflightValue},
					},
				},
			},
		}, {
			desc:       "invalid config",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
			cfg:        new(cors.Config), // invalid: no origin patterns specified
			invalid:    true,
		}, {
			desc:       "credentialed all req headers",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
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
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar,baz,foo"},
						headerACMA: {"30"},
						headerVary: {varyPreflightValue},
					},
				}, {
					desc:      "preflight with PURGE and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"bar,baz,foo,qux"},
					},
					preflight:                true,
					preflightPassesCORSCheck: true,
					preflightFails:           false, // would be true if debug were false
					respHeaders: http.Header{
						headerACAO: {"http://localhost:9090"}, // would be absent if debug were false
						headerACAC: {"true"},                  // would be absent if debug were false
						headerVary: {varyPreflightValue},
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
