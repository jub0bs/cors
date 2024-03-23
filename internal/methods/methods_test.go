package methods

import (
	"testing"

	"github.com/jub0bs/cors/internal/util"
)

func TestIsValid(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{name: "", want: false},
		{name: "GET", want: true},
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

func TestIsForbidden(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{name: "GET", want: false},
		{name: "POST", want: false},
		{name: "PUT", want: false},
		{name: "CHICKEN", want: false},
		{name: "CONNECT", want: true},
		{name: "connect", want: true},
		{name: "ConnEcT", want: true},
		{name: "TRACE", want: true},
		{name: "trace", want: true},
		{name: "trACe", want: true},
		{name: "TRACK", want: true},
		{name: "track", want: true},
		{name: "trACk", want: true},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			got := IsForbidden(tc.name)
			if got != tc.want {
				const tmpl = "%q: got %t; want %t"
				t.Errorf(tmpl, tc.name, got, tc.want)
			}
		}
		t.Run(tc.name, f)
	}
}

// This check is important because IsForbidden normalizes its argument
// by byte-lowercasing it.
func TestThatAllForbiddenMethodsAreByteLowercase(t *testing.T) {
	for method := range byteLowercasedForbiddenMethods {
		if util.ByteLowercase(method) != method {
			t.Errorf("forbidden method %q is not byte-lowercase", method)
		}
	}
}

func TestIsSafelisted(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{name: "GET", want: true},
		{name: "HEAD", want: true},
		{name: "POST", want: true},
		{name: "Get", want: false},
		{name: "Head", want: false},
		{name: "Post", want: false},
		{name: "PUT", want: false},
		{name: "DELETE", want: false},
		{name: "OPTIONS", want: false},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			got := IsSafelisted(tc.name, struct{}{})
			if got != tc.want {
				const tmpl = "%q: got %t; want %t"
				t.Errorf(tmpl, tc.name, got, tc.want)
			}
		}
		t.Run(tc.name, f)
	}
}
