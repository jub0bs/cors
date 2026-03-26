//go:build !go1.27

package origins

// splitAtCommonSuffix finds the longest suffix common to x and y and returns
// x and y both trimmed of that suffix along with the suffix itself.
func splitAtCommonSuffix(x, y string) (string, string, string) {
	// This implementation is inlineable but not free of bounds checks.
	s, l := x, y // s for short, l for long
	if len(l) < len(s) {
		s, l = l, s
	}
	i := len(s)
	l = l[len(l)-i:]
	_ = l[:i] // hoist bounds checks on l out of the loop
	for ; 0 < i && s[i-1] == l[i-1]; i-- {
		// deliberately empty body
	}
	return x[:len(x)-len(s)+i], y[:len(y)-len(s)+i], s[i:]
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
	// This implementation is neither inlineable nor free of bounds checks.
	lx, ly := len(x), len(y)
	n := min(lx, ly)
	x, y = x[lx-n:], y[ly-n:]
	_, _ = x[:n], y[:n] // hoist bounds checks out of the loop
	for i := n - 1; 0 <= i; i-- {
		switch {
		case x[i] < y[i]:
			return -1
		default:
		case x[i] > y[i]:
			return +1
		}
	}
	switch {
	case lx < ly:
		return -1
	default:
		return 0
	case lx > ly:
		return +1
	}
}
