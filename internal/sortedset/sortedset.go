// Package sortedset provides a data structure that represents a sorted set of
// strings.
package sortedset

import (
	"iter"
	"slices"
)

// A Set represents a set of strings sorted in lexicographical order.
// After a call to [*Set.Fix], each element has a unique position ranging
// from 0 (inclusive) to the set's cardinality (exclusive).
// The zero value represents an empty set.
type Set struct {
	elems  []string
	maxLen int
}

// Add adds e to s. Calling Add generally breaks the invariants of s.
func (s *Set) Add(e string) {
	s.elems = append(s.elems, e)
}

// Fix re-establishes the invariants of s.
func (s *Set) Fix() {
	slices.Sort(s.elems)
	s.elems = slices.Compact(s.elems)
	for _, e := range s.elems {
		s.maxLen = max(s.maxLen, len(e))
	}
}

// Size returns the cardinality of s.
//
// Precondition: [*Set.Add] was not called since [*Set.Fix] was last called.
func (s Set) Size() int {
	return len(s.elems)
}

// MaxLen returns the length of the longest element of s, or 0 if s is empty.
//
// Precondition: [*Set.Add] was not called since [*Set.Fix] was last called.
func (s Set) MaxLen() uint {
	return uint(s.maxLen)
}

// Contains reports whether e is an element of s.
//
// Precondition: [*Set.Add] was not called since [*Set.Fix] was last called.
func (s Set) Contains(e string) bool {
	return s.Index(0, e) >= 0
}

// Index returns the index of e in s if it occurs after the first i elements of
// s, or -1 otherwise.
//
// Precondition: [*Set.Add] was not called since [*Set.Fix] was last called.
func (s Set) Index(i uint, e string) int {
	l := uint(len(s.elems))
	if len(e) > s.maxLen || i >= l {
		return -1
	}
	// Let's binary-search for e in s.elems[i:]. We eschew
	// slices.BinarySearch here, so as to keep the method inlineable.
	for j := l; i < j; {
		h := (i + j) >> 1
		// The length check below is redundant, but it's useful because it
		// eliminates the bounds check for h.
		if h < l && s.elems[h] < e {
			i = h + 1
		} else {
			j = h
		}
	}
	if i >= l || s.elems[i] != e {
		return -1
	}
	// The following uint-to-int conversion is safe because
	// i < len(s.elems) <= math.MaxInt.
	return int(i)
}

// All returns a [pure iterator] over s's elements sorted in lexicographical order.
//
// Precondition: [*Set.Add] was not called since [*Set.Fix] was last called.
//
// [pure iterator]: https://jub0bs.com/posts/2025-05-29-pure-vs-impure-iterators-in-go/
func (s Set) All() iter.Seq[string] {
	return slices.Values(s.elems)
}
