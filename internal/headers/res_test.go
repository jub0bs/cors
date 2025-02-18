package headers

import (
	"testing"

	"github.com/jub0bs/cors/internal/util"
)

func TestIsForbiddenResponseHeaderName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{name: "x-foo", want: false},
		{name: "content-type", want: false},
		{name: "set-cookie", want: true},
		{name: "set-cookie2", want: true},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			got := IsForbiddenResponseHeaderName(tc.name)
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
func TestThatAllForbiddenResponseHeaderNamesAreByteLowercase(t *testing.T) {
	for _, name := range forbiddenResponseHeaderNames.ToSlice() {
		if util.ByteLowercase(name) != name {
			t.Errorf("forbidden response-header name %q is not byte-lowercase", name)
		}
	}
}

func TestIsProhibitedResponseHeaderName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{name: "x-foo", want: false},
		{name: "content-type", want: false},
		{name: "access-control-allow-origin", want: false},
		{name: "access-control-allow-credentials", want: false},
		{name: "access-control-expose-headers", want: false},
		{name: "origin", want: true},
		{name: "access-control-request-private-network", want: true},
		{name: "access-control-request-method", want: true},
		{name: "access-control-request-headers", want: true},
		{name: "access-control-allow-private-network", want: true},
		{name: "access-control-allow-methods", want: true},
		{name: "access-control-allow-headers", want: true},
		{name: "access-control-max-age", want: true},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			got := IsProhibitedResponseHeaderName(tc.name)
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
func TestThatAllProhibitedResponseHeaderNamesAreByteLowercase(t *testing.T) {
	for _, name := range prohibitedResponseHeaderNames.ToSlice() {
		if util.ByteLowercase(name) != name {
			t.Errorf("prohibited response-header name %q is not byte-lowercase", name)
		}
	}
}

func TestIsSafelistedResponseHeaderName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{name: "x-foo", want: false},
		{name: "cache-control", want: true},
		{name: "content-language", want: true},
		{name: "content-length", want: true},
		{name: "content-type", want: true},
		{name: "expires", want: true},
		{name: "last-modified", want: true},
		{name: "pragma", want: true},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			got := IsSafelistedResponseHeaderName(tc.name)
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
func TestThatAllSafelistedResponseHeaderNamesAreByteLowercase(t *testing.T) {
	for _, name := range safelistedResponseHeaderNames.ToSlice() {
		if util.ByteLowercase(name) != name {
			t.Errorf("safelisted response-header name %q is not byte-lowercase", name)
		}
	}
}
