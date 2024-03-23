package util_test

import (
	"testing"

	"github.com/jub0bs/cors/internal/util"
)

func TestByteLowercase(t *testing.T) {
	cases := []struct {
		str  string
		want string
	}{
		{"Authorization", "authorization"},
		{"Foo-42", "foo-42"},
	}
	for _, tc := range cases {
		got := util.ByteLowercase(tc.str)
		if got != tc.want {
			t.Errorf("%q: got %q; want %q", tc.str, got, tc.want)
		}
	}
}

func TestIsToken(t *testing.T) {
	cases := []struct {
		str  string
		want bool
	}{
		{"", false},
		{"1", true},
		{"*", true},
		{"Authorization", true},
		{"<Authorization>", false},
	}
	for _, tc := range cases {
		got := util.IsToken(tc.str)
		if got != tc.want {
			t.Errorf("%q: got %t; want %t", tc.str, got, tc.want)
		}
	}
}
