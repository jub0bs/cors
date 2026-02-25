package headers_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jub0bs/cors/internal/headers"
)

// This check is important because, otherwise, index expressions
// involving a http.Header and one of those names would yield
// unexpected results.
func Test_that_all_relevant_header_names_are_in_canonical_format(t *testing.T) {
	headerNames := []string{
		headers.Origin,
		headers.ACRM,
		headers.ACRH,
		headers.ACAO,
		headers.ACAC,
		headers.ACAM,
		headers.ACAH,
		headers.ACMA,
		headers.ACEH,
		headers.Vary,
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
func Test_that_authorization_Header_is_byte_lowercase(t *testing.T) {
	if strings.ToLower(headers.Authorization) != headers.Authorization {
		t.Errorf("%q is not byte-lowercase", headers.Authorization)
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
			t.Parallel()
			got := headers.IsValid(tc.name)
			if got != tc.want {
				const tmpl = "%q: %t; want %t"
				t.Errorf(tmpl, tc.name, got, tc.want)
			}
		}
		t.Run(tc.name, f)
	}
}

func TestFirst(t *testing.T) {
	cases := []struct {
		desc string
		h    http.Header
		key  string
		want *[1]string
		ok   bool
	}{
		{
			desc: "nil http.Header",
			h:    nil,
			key:  "Foo",
			want: nil,
			ok:   false,
		}, {
			desc: "single value",
			h: http.Header{
				"Authorization": []string{"Bearer xxx"},
			},
			key:  "Authorization",
			want: &[1]string{"Bearer xxx"},
			ok:   true,
		}, {
			desc: "multiple values",
			h: http.Header{
				"Authorization": []string{"Bearer xxx", "Basic dXNlcjpwYXNz"},
			},
			key:  "Authorization",
			want: &[1]string{"Bearer xxx"},
			ok:   true,
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			t.Parallel()
			got, ok := headers.First(tc.h, tc.key)
			if ok != tc.ok || (got == nil) != (tc.want == nil) || got != nil && got[0] != tc.want[0] {
				const tmpl = "got %q, %t; want %q, %t"
				t.Errorf(tmpl, got, ok, tc.want, tc.ok)
			}
		}
		t.Run(tc.desc, f)
	}
}
