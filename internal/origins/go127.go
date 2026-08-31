//go:build go1.27

package origins

import "strings"

// splitAtCommonSuffix finds the longest suffix common to x and y and returns
// x and y both trimmed of that suffix along with the suffix itself.
func splitAtCommonSuffix(x, y string) (string, string, string) {
	// Thanks to recent improvements to gc (specifically CL 719881),
	// this implementation is both inlineable and free of bounds checks.
	i, j := len(x), len(y)
	l := min(i, j)
	xlo, ylo := len(x)-l, len(y)-l
	for i > xlo && j > ylo {
		if x[i-1] != y[j-1] {
			return x[:i], y[:j], x[i:]
		}
		i--
		j--
	}
	return x[:xlo], y[:ylo], x[xlo:]
}

// reverseCompare returns an integer comparing two reversed strings
// lexicographically. The result will be
//   - -1 if x is less than y,
//   - 0 if x == y,
//   - +1 if x is greater than y.
//
// reverseCompare(x, y) is functionally equivalent to
//
//	bytes.Compare(slices.Reverse([]byte(x)), slices.Reverse([]byte(y)))
//
// but doesn't incur any allocation.
func reverseCompare(x, y string) int {
	// Thanks to recent improvements to gc (specifically CL 719881),
	// this implementation is both inlineable and free of bounds checks.
	for i, j := len(x)-1, len(y)-1; 0 <= i && 0 <= j; {
		switch {
		case x[i] < y[j]:
			return -1
		default:
			i--
			j--
		case x[i] > y[j]:
			return +1
		}
	}
	return intsCompare(len(x), len(y))
}

// Go 1.27 adopted Unicode 17; see
//   - https://www.unicode.org/reports/tr46/tr46-35.html
//   - https://go-review.googlesource.com/c/go/+/737420
//
// Some calls to (*idna.Profile).ToASCII that succeed with Go versions before
// 1.27 fail with Go 1.27. See https://go.dev/issue/80476.
// Without modifying the profile we rely on,
// let's remain as lenient as we were before Go 1.27.
func cleanHost(host string) string {
	// Elide an empty root label (and the preceding period), if any.
	host = strings.TrimSuffix(host, string(labelSep))
	// Replace each underscore (0x5F) character with
	// a character that can occur anywhere in a label.
	host = strings.ReplaceAll(host, "_", "a")
	return host
}
