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
						headerOrigin: {"invalid_origin"},
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
					desc:      "fake preflight with CORS-safelisted method from allowed",
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
					desc:      "fake preflight with CORS-safelisted method from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"GET"},
					},
				}, {
					desc:      "fake preflight with CORS-safelisted method from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"invalid_origin"},
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
			},
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET",
					reqMethod: "GET",
					wantRespHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "non-CORS OPTIONS",
					reqMethod: "OPTIONS",
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
					wantRespHeaders: http.Header{
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
					wantRespHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"invalid_origin"},
					},
					wantRespHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACEH: {"x-bar,x-foo"},
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				}, {
					desc:      "fake preflight with CORS-safelisted method from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with PURGE from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAM: {"PURGE"},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with PURGE and Content-Type from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"content-type"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "preflight with PURGE and Authorization from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"authorization"},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAM: {"PURGE"},
						headerACAH: {"authorization"},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with PURGE and Authorization with some empty elements from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {",,authorization,,"},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAM: {"PURGE"},
						headerACAH: {",,authorization,,"},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with PURGE and Authorization with too many empty elements from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"authorization" + strings.Repeat(",", 17)},
					},
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
				}, {
					desc:      "preflight with PURGE and Authorization with some empty ACRH header lines from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   append(make([]string, 16), "authorization"),
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAM: {"PURGE"},
						headerACAH: append(make([]string, 16), "authorization"),
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with PURGE and Authorization with too many empty ACRH header lines from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   append(make([]string, 17), "authorization"),
					},
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
				}, {
					desc:      "fake preflight with CORS-safelisted method from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"GET"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "fake preflight with CORS-safelisted method from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"invalid_origin"},
						headerACRM:   {"GET"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "preflight with PUT from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PUT"},
					},
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
				}, {
					desc:      "preflight with PUT from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"PUT"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
				}, {
					desc:      "preflight with GET and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.org"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
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
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar,baz,foo"},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with GET and headers with some OWS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar , baz\t, foo\t"},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar , baz\t, foo\t"},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with GET and headers with too much OWS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar \t, baz\t, foo\t"},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar \t, baz\t, foo\t"},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with GET and headers with some empty elements from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo" + strings.Repeat(",", 16)},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar,baz,foo" + strings.Repeat(",", 16)},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with GET and headers with too many empty elements from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo" + strings.Repeat(",", 17)},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar,baz,foo" + strings.Repeat(",", 17)},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with GET and headers with some empty ACHR header lines from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   append(make([]string, 16), "bar,baz,foo"),
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: append(make([]string, 16), "bar,baz,foo"),
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with GET and headers with too many empty ACHR header lines from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   append(make([]string, 17), "bar,baz,foo"),
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: append(make([]string, 17), "bar,baz,foo"),
						headerACMA: {"30"},
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
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
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
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
					},
				}, {
					desc:      "preflight with disallowed method",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PUT"},
					},
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
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
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"authorization"},
						headerACMA: {"30"},
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
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {wildcard},
						headerACAM: {wildcard},
						headerACAH: {wildcard},
						headerACMA: {"30"},
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
			},
			debug: true,
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET request",
					reqMethod: "GET",
					wantRespHeaders: http.Header{
						headerACAO: {wildcard},
						headerACEH: {wildcard},
					},
				}, {
					desc:      "non-CORS OPTIONS request",
					reqMethod: "OPTIONS",
					wantRespHeaders: http.Header{
						headerACAO: {wildcard},
						headerACEH: {wildcard},
					},
				}, {
					desc:      "actual GET request",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {wildcard},
						headerACEH: {wildcard},
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"invalid_origin"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {wildcard},
						headerACEH: {wildcard},
					},
				}, {
					desc:      "actual OPTIONS request",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {wildcard},
						headerACEH: {wildcard},
					},
				}, {
					desc:      "fake preflight with CORS-safelisted method",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {wildcard},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with PURGE",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {wildcard},
						headerACAM: {wildcard},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with PURGE and Content-Type",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"content-type"},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {wildcard},
						headerACAM: {wildcard},
						headerACAH: {wildcardAndAuth},
						headerACMA: {"30"},
					},
				}, {
					desc:      "fake preflight with CORS-safelisted method from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"invalid_origin"},
						headerACRM:   {"GET"},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {wildcard},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with PUT",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PUT"},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {wildcard},
						headerACAM: {wildcard},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with GET and headers",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {wildcard},
						headerACAH: {wildcardAndAuth},
						headerACMA: {"30"},
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
			},
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET request",
					reqMethod: "GET",
					wantRespHeaders: http.Header{
						headerVary: {headers.Origin},
					},
				}, {
					desc:      "non-CORS OPTIONS request",
					reqMethod: "OPTIONS",
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com:8080"},
					},
					wantRespHeaders: http.Header{
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
					wantRespHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"invalid_origin"},
					},
					wantRespHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com:8080"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"https://example.com:8080"},
						headerACAC: {"true"},
						headerACEH: {"x-bar,x-foo"},
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://foo.example.com:8080"},
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com:8080"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"https://example.com:8080"},
						headerACAC: {"true"},
						headerACAH: {"bar,baz,foo"},
						headerACMA: {"30"},
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
					wantRespHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "non-CORS OPTIONS",
					reqMethod: "OPTIONS",
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
					wantRespHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"invalid_origin"},
					},
					wantRespHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
					},
				}, {
					desc:      "fake preflight with CORS-safelisted method from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "preflight with PURGE from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
					},
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
				}, {
					desc:      "preflight with PURGE and Content-Type from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"content-type"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "fake preflight with CORS-safelisted method from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"GET"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "fake preflight with CORS-safelisted method from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"invalid_origin"},
						headerACRM:   {"GET"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "preflight with PUT from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PUT"},
					},
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
				}, {
					desc:      "preflight with PUT from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"PUT"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
				}, {
					desc:      "preflight with GET and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.org"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
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
					wantRespHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from disallowed 2",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://foobar.com"},
					},
					wantRespHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://barfoo.com"},
					},
				}, {
					desc:      "actual OPTIONS from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://foobar.com"},
					},
				}, {
					desc:      "fake preflight with CORS-safelisted method from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://barfoo.com"},
						headerACRM:   {"GET"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "fake preflight with CORS-safelisted method from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://foobar.com"},
						headerACRM:   {"GET"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "preflight with PUT from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://barfoo.com"},
						headerACRM:   {"PUT"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "preflight with PUT from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://foobar.com"},
						headerACRM:   {"PUT"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "preflight with GET and headers from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://barfoo.com"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "preflight with GET and headers from disallowed 2",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://foobar.com"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				},
			},
		}, {
			desc:       "insecure origin with non-HTTP scheme",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
			cfg: &cors.Config{
				Origins: []string{
					"connector://example.com",
				},
				Credentialed:                       true,
				DangerouslyTolerateInsecureOrigins: true,
			},
			cases: []ReqTestCase{
				{
					desc:      "non-CORS GET request",
					reqMethod: "GET",
					wantRespHeaders: http.Header{
						headerVary: {headers.Origin},
					},
				}, {
					desc:      "non-CORS OPTIONS request",
					reqMethod: "OPTIONS",
				}, {
					desc:      "actual GET from allowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"connector://example.com"},
					},
					wantRespHeaders: http.Header{
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
					wantRespHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from invalid",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"invalid_origin"},
					},
					wantRespHeaders: http.Header{
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual OPTIONS from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"connector://example.com"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"connector://example.com"},
						headerACAC: {"true"},
					},
				}, {
					desc:      "actual OPTIONS from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"connector://example.com:8080"},
					},
				}, {
					desc:      "preflight with GET and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"connector://example.com"},
						headerACRM:   {"GET"},
						headerACRH:   {"bar,baz,foo"},
					},
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
				},
			},
		}, {
			desc:       "arbitrary subdomains and arbitrary ports",
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
					wantRespHeaders: http.Header{
						headerACAO: {"http://foo.example.com"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from subdomain and port",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://foo.example.com:6060"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"http://foo.example.com:6060"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from deeper subdomain",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://bar.foo.example.com"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"http://bar.foo.example.com"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from deeper subdomain and port",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://bar.foo.example.com:8080"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"http://bar.foo.example.com:8080"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from disallowed",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"http://example.com"},
					},
					wantRespHeaders: http.Header{
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
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
				},
			},
		}, {
			desc:       "many origins",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
			cfg: &cors.Config{
				Origins: []string{
					"https://bat",
					"https://cat",
					"https://fat",
					"https://hat",
					"https://meerkat",
					"https://mat",
					"https://oat",
					"https://pat",
					"https://rat",
					"https://sat",
				},
			},
			cases: []ReqTestCase{
				{
					desc:      "actual GET from https://bat",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://bat"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"https://bat"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from https://cat",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://cat"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"https://cat"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from https://fat",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://fat"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"https://fat"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from https://hat",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://hat"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"https://hat"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from https://meerkat",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://meerkat"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"https://meerkat"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from https://mat",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://mat"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"https://mat"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from https://oat",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://oat"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"https://oat"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from https://pat",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://pat"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"https://pat"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from https://rat",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://rat"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"https://rat"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from https://sat",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://sat"},
					},
					wantRespHeaders: http.Header{
						headerACAO: {"https://sat"},
						headerVary: {headerOrigin},
					},
				}, {
					desc:      "actual GET from https://hazmat",
					reqMethod: "GET",
					reqHeaders: http.Header{
						headerOrigin: {"https://hazmat"},
					},
					wantRespHeaders: http.Header{
						headerVary: {headerOrigin},
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
					t.Parallel()
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
					if tc.wantOutcome.isPreflight() { // preflight request
						if spy.called.Load() {
							t.Error("wrapped handler was called, but it should not have been")
						}
						assertPreflightStatus(t, spy.statusCode, res.StatusCode, &mwtc, &tc)
						wantHeaders := []http.Header{tc.wantRespHeaders}
						if mwtc.outerMw != nil {
							wantHeaders = append(wantHeaders, mwtc.outerMw.hdrs)
						}
						assertHeadersEqual(t, res.Header, wantHeaders...)
						assertBodyEqual(t, res.Body, "")
						return
					} // non-preflight request
					if !spy.called.Load() {
						t.Error("wrapped handler wasn't called, but it should have been")
					}
					if res.StatusCode != spy.statusCode {
						const tmpl = "got status code %d; want %d"
						t.Errorf(tmpl, res.StatusCode, spy.statusCode)
					}
					wantHeaders := []http.Header{spy.respHeaders, tc.wantRespHeaders}
					if mwtc.outerMw != nil {
						wantHeaders = append(wantHeaders, mwtc.outerMw.hdrs)
					}
					assertHeadersEqual(t, res.Header, wantHeaders...)

					assertBodyEqual(t, res.Body, spy.body)
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
						headerOrigin: {"invalid_origin"},
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
					desc:      "fake preflight with CORS-safelisted method from allowed",
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
					desc:      "fake preflight with CORS-safelisted method from disallowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"https://example.com"},
						headerACRM:   {"GET"},
					},
				}, {
					desc:      "fake preflight with CORS-safelisted method from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"invalid_origin"},
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
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
					},
				}, {
					desc:      "preflight with PUT from invalid",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"invalid_origin"},
						headerACRM:   {"PUT"},
					},
					wantOutcome: isPreflightAndFailsDuringCORSCheck,
				}, {
					desc:      "preflight with disallowed method",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PUT"},
					},
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
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
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar,baz,foo"},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with PURGE and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"bar,baz,foo,qux"},
					},
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
				},
			},
		}, {
			desc:       "invalid config",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
			cfg:        new(cors.Config), // invalid: no origin patterns specified
			invalid:    true,
		}, {
			desc:       "credentialed all req headers again",
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
			cfg: &cors.Config{
				Origins:         []string{"http://localhost:9090"},
				Credentialed:    true,
				RequestHeaders:  []string{"*"},
				MaxAgeInSeconds: 30,
				ResponseHeaders: []string{"X-Foo", "X-Bar"},
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
					wantOutcome: isPreflightAndSucceeds,
					wantRespHeaders: http.Header{
						headerACAO: {"http://localhost:9090"},
						headerACAC: {"true"},
						headerACAH: {"bar,baz,foo"},
						headerACMA: {"30"},
					},
				}, {
					desc:      "preflight with PURGE and headers from allowed",
					reqMethod: "OPTIONS",
					reqHeaders: http.Header{
						headerOrigin: {"http://localhost:9090"},
						headerACRM:   {"PURGE"},
						headerACRH:   {"bar,baz,foo,qux"},
					},
					wantOutcome: isPreflightAndFailsAfterCORSCheck,
				},
			},
		}, {
			desc:       "passthrough again", // once more, in order to test debug
			newHandler: newSpyHandler(200, http.Header{headerVary: {"foo"}}, "bar"),
			cfg:        nil,
		},
	}
	var mw cors.Middleware
	var oldDebug bool
	for _, mwtc := range cases {
		f := func(t *testing.T) {
			// No t.Parallel() here: these cases must be run sequentially.
			err := mw.Reconfigure(mwtc.cfg)
			if err != nil && !mwtc.invalid {
				t.Fatalf("failure to reconfigure CORS middleware: %v", err)
			}
			if err == nil && mwtc.invalid {
				t.Fatal("unexpected absence of failure to reconfigure CORS middleware")
			}
			currentDebug := mw.Debug()
			if currentDebug != oldDebug {
				// Reconfiguring a middleware should preserve its debug mode.
				const tmpl = "unexpected debug mode: got %t; want %t"
				t.Fatalf(tmpl, currentDebug, oldDebug)
			}
			mw.SetDebug(mwtc.debug)
			oldDebug = mwtc.debug
			for _, tc := range mwtc.cases {
				f := func(t *testing.T) {
					t.Parallel()
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
					if tc.wantOutcome.isPreflight() { // preflight request
						if spy.called.Load() {
							t.Error("wrapped handler was called, but it should not have been")
						}
						assertPreflightStatus(t, spy.statusCode, res.StatusCode, &mwtc, &tc)
						wantHeaders := []http.Header{tc.wantRespHeaders}
						if mwtc.outerMw != nil {
							wantHeaders = append(wantHeaders, mwtc.outerMw.hdrs)
						}
						assertHeadersEqual(t, res.Header, wantHeaders...)
						assertBodyEqual(t, res.Body, "")
						return
					} // non-preflight request
					if !spy.called.Load() {
						t.Error("wrapped handler wasn't called, but it should have been")
					}
					if res.StatusCode != spy.statusCode {
						const tmpl = "got status code %d; want %d"
						t.Errorf(tmpl, res.StatusCode, spy.statusCode)
					}
					wantHeaders := []http.Header{spy.respHeaders, tc.wantRespHeaders}
					if mwtc.outerMw != nil {
						wantHeaders = append(wantHeaders, mwtc.outerMw.hdrs)
					}
					assertHeadersEqual(t, res.Header, wantHeaders...)
					assertBodyEqual(t, res.Body, spy.body)
				}
				t.Run(tc.desc, f)
			}
		}
		t.Run(mwtc.desc, f)
	}
}

func Test_mutation_by_wrapping_middleware(t *testing.T) {
	cors, err := cors.NewMiddleware(cors.Config{
		Origins:      []string{"https://example.com"},
		Methods:      []string{http.MethodPut},
		Credentialed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	dummyHandler := func(_ http.ResponseWriter, _ *http.Request) {}
	mutatingMiddleware := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
			w.Header()["Access-Control-Allow-Credentials"][0] = "oops!"
		})
	}
	h := mutatingMiddleware(cors.Wrap(http.HandlerFunc(dummyHandler)))

	req := httptest.NewRequest("OPTIONS", "https://example.org", nil)
	req.Header.Add("Origin", "https://example.com")
	req.Header.Add("Access-Control-Request-Method", http.MethodPut)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	acac := rec.Result().Header.Get("Access-Control-Allow-Credentials")
	if acac != "true" {
		t.Fatalf("ACAO: got %q; want \"true\"", acac)
	}
}
