package headers

import (
	"testing"

	"github.com/jub0bs/cors/internal/util"
)

func TestIsForbiddenRequestHeaderName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{name: "authorization", want: false},
		{name: "content-type", want: false},
		{name: "origin", want: true},
		{name: "access-control-request-private-network", want: true},
		{name: "access-control-request-method", want: true},
		{name: "access-control-request-headers", want: true},
		{name: "proxy-foo", want: true},
		{name: "sec-foo", want: true},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			got := IsForbiddenRequestHeaderName(tc.name)
			if got != tc.want {
				const tmpl = "%q: got %t; want %t"
				t.Errorf(tmpl, tc.name, got, tc.want)
			}
		}
		t.Run(tc.name, f)
	}
}

// This check is important because, otherwise, index expressions
// involving a http.Header and one of those names would yield
// unexpected results.
func TestThatAllDiscreteForbiddenRequestHeaderNamesAreByteLowercase(t *testing.T) {
	for name := range discreteForbiddenRequestHeaderNames {
		if util.ByteLowercase(name) != name {
			t.Errorf("forbidden header name %q is not byte-lowercase", name)
		}
	}
}

func TestIsProhibitedRequestHeaderName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{name: "authorization", want: false},
		{name: "content-type", want: false},
		{name: "access-control-allow-origin", want: true},
		{name: "access-control-allow-credentials", want: true},
		{name: "access-control-allow-private-network", want: true},
		{name: "access-control-allow-methods", want: true},
		{name: "access-control-allow-headers", want: true},
		{name: "access-control-max-age", want: true},
		{name: "access-control-expose-headers", want: true},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			got := IsProhibitedRequestHeaderName(tc.name)
			if got != tc.want {
				const tmpl = "%q: got %t; want %t"
				t.Errorf(tmpl, tc.name, got, tc.want)
			}
		}
		t.Run(tc.name, f)
	}
}

// This check is important because, otherwise, index expressions
// involving a http.Header and one of those names would yield
// unexpected results.
func TestThatAllProhibitedRequestHeaderNamesAreByteLowercase(t *testing.T) {
	for name := range prohibitedRequestHeaderNames {
		if util.ByteLowercase(name) != name {
			t.Errorf("prohibited header name %q is not byte-lowercase", name)
		}
	}
}
