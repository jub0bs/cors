package util_test

import (
	"testing"
	"unicode/utf8"

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

func TestByteUppercase(t *testing.T) {
	cases := []struct {
		str  string
		want string
	}{
		{"Authorization", "AUTHORIZATION"},
		{"Foo-42", "FOO-42"},
	}
	for _, tc := range cases {
		got := util.ByteUppercase(tc.str)
		if got != tc.want {
			t.Errorf("%q: got %q; want %q", tc.str, got, tc.want)
		}
	}
}

func FuzzUpperThenLowerHasNoEffectAfterLower(f *testing.F) {
	testcases := []string{
		"Authorization",
		"Foo-42",
	}
	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, orig string) {
		lower := util.ByteLowercase(orig)
		lower2 := util.ByteLowercase(util.ByteUppercase(lower))
		if lower != lower2 {
			const tmpl = "L(%q): %q; L(U(L(%q))): %q"
			t.Errorf(tmpl, orig, lower, orig, lower2)
		}
	})
}

func FuzzLowerThenUpperHasNoEffectAfterUpper(f *testing.F) {
	testcases := []string{
		"Authorization",
		"Foo-42",
	}
	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, orig string) {
		if !isASCII(orig) {
			t.Skip()
		}
		upper := util.ByteUppercase(orig)
		upper2 := util.ByteUppercase(util.ByteLowercase(upper))
		if upper != upper2 {
			const tmpl = "U(%q): %q; U(L(U(%q))): %q"
			t.Errorf(tmpl, orig, upper, orig, upper2)
		}
	})
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
