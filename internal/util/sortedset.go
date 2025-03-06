package util

import "slices"

// A SortedSet represents a set of strings sorted in lexicographical order.
// Each element has a unique position ranging from 0 (inclusive) to the set's
// cardinality (exclusive).
// The zero value represents an empty set.
type SortedSet struct {
	elems  []string // invariant: sorted
	maxLen int
}

// Add adds e to set.
func (set *SortedSet) Add(e string) {
	_, found := slices.BinarySearch(set.elems, e)
	if found {
		return
	}
	set.elems = append(set.elems, e)
	slices.Sort(set.elems)
	set.maxLen = max(set.maxLen, len(e))
}

// Size returns the cardinality of set.
func (set SortedSet) Size() int {
	return len(set.elems)
}

// MaxLen returns the length of set's longest element,
// or 0 if set is empty.
func (set SortedSet) MaxLen() int {
	return set.maxLen
}

// IndexAfter returns the position of e in set if it occurs
// after the first n+1 elements of set, or -1 otherwise.
//
// Precondition: n < set.Size().
func (set SortedSet) IndexAfter(n int, e string) int {
	if set.maxLen < len(e) {
		return -1
	}
	start := n + 1
	i, found := slices.BinarySearch(set.elems[start:], e)
	if !found {
		return -1
	}
	return start + i
}

// ToSlice returns a slice of set's elements sorted in lexicographical order.
func (set SortedSet) ToSlice() []string {
	// We need defensive copying here because clients can mutate the result;
	// see (*cors.Middleware).Config.
	return slices.Clone(set.elems)
}
