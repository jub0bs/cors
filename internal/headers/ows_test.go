package headers_test

import (
	"testing"

	"github.com/jub0bs/cors/internal/headers"
)

const maxOWSBytes = 1

var trimOWStests = []struct {
	desc string
	s    string
	want string
	ok   bool
}{
	{
		desc: "empty",
		s:    "",
		want: "",
		ok:   true,
	}, {
		desc: "no OWS",
		s:    "foo",
		want: "foo",
		ok:   true,
	}, {
		desc: "internal OWS",
		s:    "foo  \t\tbar",
		want: "foo  \t\tbar",
		ok:   true,
	}, {
		desc: "leading and trailing OWS",
		s:    "\tfoo ",
		want: "foo",
		ok:   true,
	}, {
		desc: "too much leading OWS",
		s:    " \tfoo\t",
		ok:   false,
	}, {
		desc: "too much trailing OWS",
		s:    " foo\t ",
		ok:   false,
	}, {
		desc: "too much leading and trailing OWS",
		s:    " \tfoo\t ",
		ok:   false,
	}, {
		desc: "non-OWS whitespace",
		s:    "\nfoo\t",
		want: "\nfoo",
		ok:   true,
	}, {
		desc: "a tolerated amount of OWS and nothing else",
		s:    "\t ",
		want: "",
		ok:   true,
	}, {
		desc: "a tolerated amount of OWS around non-OWS",
		s:    " a ",
		want: "a",
		ok:   true,
	},
}

func TestTrimOWS(t *testing.T) {
	for _, tc := range trimOWStests {
		f := func(t *testing.T) {
			got, ok := headers.TrimOWS(tc.s, maxOWSBytes)
			if !tc.ok && ok {
				// In cases where TrimOWS must fail, its string result is
				// unspecified.
				const tmpl = "headers.TrimOWS(%q, %d): got _, %t; want _, %t"
				t.Fatalf(tmpl, tc.s, maxOWSBytes, ok, tc.ok)
			}
			if tc.ok && (!ok || got != tc.want) {
				const tmpl = "headers.TrimOWS(%q, %d): got %q, %t; want %q, %t"
				t.Errorf(tmpl, tc.s, maxOWSBytes, got, ok, tc.want, tc.ok)
			}
		}
		t.Run(tc.desc, f)
	}
}

func BenchmarkTrimOWS(b *testing.B) {
	for _, tc := range trimOWStests {
		f := func(b *testing.B) {
			for range b.N {
				headers.TrimOWS(tc.s, maxOWSBytes)
			}
		}
		b.Run(tc.desc, f)
	}
}
