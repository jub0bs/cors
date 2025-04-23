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
		want: " \tfoo\t",
		ok:   false,
	}, {
		desc: "too much trailing OWS",
		s:    " foo\t ",
		want: " foo\t ",
		ok:   false,
	}, {
		desc: "too much leading and trailing OWS",
		s:    " \tfoo\t ",
		want: " \tfoo\t ",
		ok:   false,
	}, {
		desc: "non-OWS whitespace",
		s:    "\nfoo\t",
		want: "\nfoo",
		ok:   true,
	},
}

func TestTrimOWS(t *testing.T) {
	for _, tc := range trimOWStests {
		f := func(t *testing.T) {
			got, ok := headers.TrimOWS(tc.s, maxOWSBytes)
			if ok != tc.ok || got != tc.want {
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
