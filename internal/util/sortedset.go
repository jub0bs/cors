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

// Index returns the index of e in set if it occurs after the first n elements
// of set, or -1 otherwise.
//
// Precondition: [*SortedSet.Add] was not called since [*SortedSet.Fix] was
// last called.
func (set SortedSet) Index(n uint, e string) int {
	if set.maxLen < len(e) || uint(len(set.elems)) < n {
		return -1
	}
	// Let's binary-search for e in set.elems[n:]. We eschew
	// slices.BinarySearch here, so as to keep the method inlineable.
	s := set.elems[n:]
	var i uint
	for j := uint(len(s)); i < j; {
		j += i
		j >>= 1
		// The length check below is redundant, but it's useful because it
		// eliminates the bounds check for j.
		if j < uint(len(s)) && s[j] < e {
			i = j + 1
		}
	}
	if i >= uint(len(s)) || s[i] != e {
		return -1
	}
	// The following uint-to-int conversion is safe because
	// n + i < len(set.elems) <= math.MaxInt.
	return int(n + i)
}

// ToSlice returns a slice of set's elements sorted in lexicographical order.
//
// Precondition: [*SortedSet.Add] was not called since [*SortedSet.Fix] was
// last called.
func (set SortedSet) ToSlice() []string {
	return slices.Clone(set.elems) // defensive copying
}
