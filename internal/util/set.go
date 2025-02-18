package util

import "slices"

// A Set represents a set of strings.
type Set map[string]struct{}

// NewSet returns a Set that contains all of elems
// but no other elements.
func NewSet(elems ...string) Set {
	set := make(Set)
	for _, e := range elems {
		set.Add(e)
	}
	return set
}

// Add adds e to set.
func (set Set) Add(e string) {
	set[e] = struct{}{}
}

// Contains reports whether e is an element of set.
func (set Set) Contains(e string) bool {
	_, found := set[e]
	return found
}

// Size returns the cardinality of set.
func (set Set) Size() int {
	return len(set)
}

// ToSlice returns a slice of set's elements sorted in lexicographical order.
func (s Set) ToSlice() []string {
	res := make([]string, 0, len(s))
	for elem := range s {
		res = append(res, elem)
	}
	slices.Sort(res)
	return res
}
