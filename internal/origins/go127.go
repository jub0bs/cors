//go:build go1.27

package origins

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
	switch {
	case len(x) < len(y):
		return -1
	default:
		return 0
	case len(x) > len(y):
		return +1
	}
}
