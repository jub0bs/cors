// Package util provides a data structure that represents a sorted set of
// strings.
package util

import "slices"

// A SortedSet represents a set of strings sorted in lexicographical order.
// After a call to [*SortedSet.Fix], each element has a unique position ranging
// from 0 (inclusive) to the set's cardinality (exclusive).
// The zero value represents an empty set.
type SortedSet struct {
	elems  []string
	maxLen int
}

// Add adds e to set. Calling Add generally breaks set's invariants.
func (set *SortedSet) Add(e string) {
	set.elems = append(set.elems, e)
}

// Fix re-establishes set's invariants.
func (set *SortedSet) Fix() {
	slices.Sort(set.elems)
	set.elems = slices.Compact(set.elems)
	for _, e := range set.elems {
		set.maxLen = max(set.maxLen, len(e))
	}
}

// Size returns the cardinality of set.
//
// Precondition: [*SortedSet.Add] was not called since [*SortedSet.Fix] was
// last called.
func (set SortedSet) Size() int {
	return len(set.elems)
}

// MaxLen returns the length of set's longest element, or 0 if set is empty.
//
// Precondition: [*SortedSet.Add] was not called since [*SortedSet.Fix] was
// last called.
func (set SortedSet) MaxLen() uint {
	return uint(set.maxLen)
}

// Contains reports whether e is an element of set.
//
// Precondition: [*SortedSet.Add] was not called since [*SortedSet.Fix] was
// last called.
func (set SortedSet) Contains(e string) bool {
	return set.Index(0, e) >= 0
}

// Index returns the index of e in set if it occurs after the first i elements
// of set, or -1 otherwise.
//
// Precondition: [*SortedSet.Add] was not called since [*SortedSet.Fix] was
// last called.
func (set SortedSet) Index(i uint, e string) int {
	l := uint(len(set.elems))
	if len(e) > set.maxLen || i >= l {
		return -1
	}
	// Let's binary-search for e in set.elems[i:]. We eschew
	// slices.BinarySearch here, so as to keep the method inlineable.
	for j := l; i < j; {
		h := (i + j) >> 1
		// The length check below is redundant, but it's useful because it
		// eliminates the bounds check for h.
		if h < l && set.elems[h] < e {
			i = h + 1
		} else {
			j = h
		}
	}
	if i >= l || set.elems[i] != e {
		return -1
	}
	// The following uint-to-int conversion is safe because
	// i < len(set.elems) <= math.MaxInt.
	return int(i)
}

// ToSlice returns a slice of set's elements sorted in lexicographical order.
//
// Precondition: [*SortedSet.Add] was not called since [*SortedSet.Fix] was
// last called.
func (set SortedSet) ToSlice() []string {
	return slices.Clone(set.elems) // defensive copying
}
