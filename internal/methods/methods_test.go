package methods_test

import (
	"testing"

	"github.com/jub0bs/cors/internal/methods"
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
			got := methods.IsValid(tc.name)
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
			got := methods.IsForbidden(tc.name)
			if got != tc.want {
				const tmpl = "%q: got %t; want %t"
				t.Errorf(tmpl, tc.name, got, tc.want)
			}
		}
		t.Run(tc.name, f)
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
			got := methods.IsSafelisted(tc.name)
			if got != tc.want {
				const tmpl = "%q: got %t; want %t"
				t.Errorf(tmpl, tc.name, got, tc.want)
			}
		}
		t.Run(tc.name, f)
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{name: "DELETE", want: "DELETE"},
		{name: "GET", want: "GET"},
		{name: "HEAD", want: "HEAD"},
		{name: "OPTIONS", want: "OPTIONS"},
		{name: "POST", want: "POST"},
		{name: "PUT", want: "PUT"},
		//
		{name: "Delete", want: "DELETE"},
		{name: "geT", want: "GET"},
		{name: "heAd", want: "HEAD"},
		{name: "OPTIONs", want: "OPTIONS"},
		{name: "PosT", want: "POST"},
		{name: "put", want: "PUT"},
		//
		{name: "PATCH", want: "PATCH"},
		{name: "patch", want: "patch"},
		{name: "QUERY", want: "QUERY"},
		{name: "query", want: "query"},
		{name: "chicken", want: "chicken"},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			got := methods.Normalize(tc.name)
			if got != tc.want {
				const tmpl = "%q: got %q; want %q"
				t.Errorf(tmpl, tc.name, got, tc.want)
			}
		}
		t.Run(tc.name, f)
	}
}
