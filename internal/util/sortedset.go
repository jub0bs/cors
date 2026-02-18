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
	maxLen uint
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
		set.maxLen = max(set.maxLen, uint(len(e)))
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
	return set.maxLen
}

// Contains reports whether e is an element of set.
//
// Precondition: [*SortedSet.Add] was not called since [*SortedSet.Fix] was
// last called.
func (set SortedSet) Contains(e string) bool {
	return set.IndexAfter(-1, e) >= 0
}

// IndexAfter returns the position of e in set if it occurs after the first
// n+1 elements of set, or -1 otherwise.
//
// Preconditions:
//   - n < set.Size(), and
//   - [*SortedSet.Add] was not called since [*SortedSet.Fix] was last called.
func (set SortedSet) IndexAfter(n int, e string) int {
	if set.maxLen < uint(len(e)) {
		return -1
	}
	n++
	i, found := slices.BinarySearch(set.elems[n:], e)
	if !found {
		return -1
	}
	return n + i
}

// ToSlice returns a slice of set's elements sorted in lexicographical order.
//
// Precondition: [*SortedSet.Add] was not called since [*SortedSet.Fix] was
// last called.
func (set SortedSet) ToSlice() []string {
	return slices.Clone(set.elems) // defensive copying
}
