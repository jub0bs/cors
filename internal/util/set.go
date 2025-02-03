package util

import "slices"

// A Set represents a set of strings.
type Set map[string]struct{}

// NewSet returns a Set that contains all of elems,
// but no other elements.
func NewSet(elems ...string) Set {
	set := make(Set)
	for _, e := range elems {
		set.Add(e)
	}
	return set
}

// Add adds e to s.
func (s Set) Add(e string) {
	s[e] = struct{}{}
}

// Contains returns true if e is an element of s, and false otherwise.
func (s Set) Contains(e string) bool {
	_, found := s[e]
	return found
}

// Size returns the cardinality of s.
func (s Set) Size() int {
	return len(s)
}

// ToSortedSlice returns a sorted slice of s's elements.
func (s Set) ToSortedSlice() []string {
	res := make([]string, 0, len(s))
	for elem := range s {
		res = append(res, elem)
	}
	slices.Sort(res)
	return res
}
