package headers

import (
	"maps"
	"net/http"
	"slices"
	"testing"

	"github.com/jub0bs/cors/internal/util"
)

// This check is important because, otherwise, index expressions
// involving a http.Header and one of those names would yield
// unexpected results.
func TestThatAllRelevantHeaderNamesAreInCanonicalFormat(t *testing.T) {
	headerNames := []string{
		Origin,
		ACRPN,
		ACRM,
		ACRH,
		ACAO,
		ACAC,
		ACAPN,
		ACAM,
		ACAH,
		ACMA,
		ACEH,
		Vary,
	}
	for _, name := range headerNames {
		if http.CanonicalHeaderKey(name) != name {
			t.Errorf("header name %q is not in canonical format", name)
		}
	}
}

// This check doesn't matter much, since we never use this name has a
// http.Header key; however, for consistency, we prefer consistently writing
// byte-lowercase header values in CORS response headers.
func TestThatAuthorizationHeaderIsByteLowercase(t *testing.T) {
	if util.ByteLowercase(Authorization) != Authorization {
		t.Errorf("%q is not byte-lowercase", Authorization)
	}
}

func TestIsValid(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{name: "", want: false},
		{name: "authorization", want: true},
		{name: "()", want: false},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			got := IsValid(tc.name)
			if got != tc.want {
				const tmpl = "%q: got %t; want %t"
				t.Errorf(tmpl, tc.name, got, tc.want)
			}
		}
		t.Run(tc.name, f)
	}
}

func TestFastAdd(t *testing.T) {
	cases := []struct {
		desc  string
		h     http.Header
		key   string
		value []string
		want  http.Header
	}{
		{
			desc:  "empty http.Header",
			h:     http.Header{},
			key:   "Foo",
			value: []string{"bar"},
			want:  http.Header{"Foo": []string{"bar"}},
		}, {
			desc: "single value",
			h: http.Header{
				"Authorization": []string{"Bearer xxx"},
			},
			key:   "Authorization",
			value: []string{"Basic dXNlcjpwYXNz"},
			want: http.Header{
				"Authorization": []string{
					"Bearer xxx",
					"Basic dXNlcjpwYXNz",
				},
			},
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			FastAdd(tc.h, tc.key, tc.value)
			if !maps.EqualFunc(tc.h, tc.want, slices.Equal) {
				t.Errorf("got %q; want %q", tc.h, tc.want)
			}
		}
		t.Run(tc.desc, f)
	}
}

func TestFirst(t *testing.T) {
	cases := []struct {
		desc string
		h    http.Header
		key  string
		want string
		ok   bool
	}{
		{
			desc: "nil http.Header",
			h:    nil,
			key:  "Foo",
			want: "",
			ok:   false,
		}, {
			desc: "single value",
			h: http.Header{
				"Authorization": []string{"Bearer xxx"},
			},
			key:  "Authorization",
			want: "Bearer xxx",
			ok:   true,
		}, {
			desc: "multiple values",
			h: http.Header{
				"Authorization": []string{"Bearer xxx", "Basic dXNlcjpwYXNz"},
			},
			key:  "Authorization",
			want: "Bearer xxx",
			ok:   true,
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			v, s, ok := First(tc.h, tc.key)
			if ok != tc.ok || v != tc.want || len(s) > 1 || len(s) == 1 && s[0] != v {
				const tmpl = "got %s, %q, %t; want %s, %q, %t"
				t.Errorf(tmpl, v, s, ok, tc.want, []string{tc.want}, tc.ok)
			}
		}
		t.Run(tc.desc, f)
	}
}
