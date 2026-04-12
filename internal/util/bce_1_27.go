//go:build go1.27

package util

// Index returns the index of e in set if it occurs after the first n elements
// of set, or -1 otherwise.
//
// Precondition: [*SortedSet.Add] was not called since [*SortedSet.Fix] was
// last called.
func (set SortedSet) Index(n uint, e string) int {
	if len(e) > set.maxLen || n >= uint(len(set.elems)) {
		return -1
	}
	s := set.elems[n:]
	// Let's binary-search for e in s;
	// we eschew slices.BinarySearch so as to keep the method inlineable.
	i, j := 0, len(s)
	for i < j {
		h := int(uint(i+j) >> 1)
		if s[h] < e {
			i = h + 1
		} else {
			j = h
		}
	}
	if i >= len(s) || s[i] != e {
		return -1
	}
	// The following uint-to-int conversion is safe because
	// n < len(set.elems) <= math.MaxInt.
	return i + int(n)
}
