//go:build !go1.27

package util

// Index returns the index of e in set if it occurs after the first n elements
// of set, or -1 otherwise.
//
// Precondition: [*SortedSet.Add] was not called since [*SortedSet.Fix] was
// last called.
func (set SortedSet) Index(n uint, e string) int {
	l := uint(len(set.elems))
	if len(e) > set.maxLen || n >= l {
		return -1
	}
	// Let's binary-search for e in set.elems[n:]. We eschew
	// slices.BinarySearch here, so as to keep the method inlineable.
	for j := l; n < j; {
		j += n
		j >>= 1
		// The length check below is redundant, but it's useful because it
		// eliminates the bounds check for j.
		// CL 763460 will render such check unnecessary.
		if j < l && set.elems[j] < e {
			n = j + 1
		}
	}
	if n >= l || set.elems[n] != e {
		return -1
	}
	// The following uint-to-int conversion is safe because
	// n < len(set.elems) <= math.MaxInt.
	return int(n)
}
