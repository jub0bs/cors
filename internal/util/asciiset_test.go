package util

import (
	"math"
	"testing"
)

func TestASCIISet(t *testing.T) {
	cases := []struct {
		elems string
	}{
		{" \t"},
		{"0123456789abcdef"},
	}
	for _, tc := range cases {
		// create a reference set
		set := make(map[byte]struct{}, len(tc.elems))
		for i := range len(tc.elems) {
			set[tc.elems[i]] = struct{}{}
		}
		asciiset := MakeASCIISet(tc.elems)
		var b byte
		for ; b < math.MaxUint8; b++ {
			_, want := set[b]
			got := asciiset.Contains(b)
			if got != want {
				const tmpl = "MakeASCIISet(%q).Contains(%q): got %t; want %t"
				t.Errorf(tmpl, tc.elems, b, got, want)
			}
		}
	}
}
