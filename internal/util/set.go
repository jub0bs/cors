package util

// A Set represents a set of strings.
type Set SortedSet

// NewSet returns a Set that contains all of elems
// but no other elements.
func NewSet(elems ...string) (set Set) {
	// We don't need defensive copying here because clients cannot hold
	// a reference to this function's slice argument.
	for _, e := range elems {
		set.Add(e)
	}
	return
}

// Add adds e to set.
func (set *Set) Add(e string) {
	(*SortedSet)(set).Add(e)
}

// Contains reports whether e is an element of set.
func (set Set) Contains(e string) bool {
	return SortedSet(set).IndexAfter(-1, e) >= 0
}

// Size returns the cardinality of set.
func (set Set) Size() int {
	return SortedSet(set).Size()
}

// ToSlice returns a slice of set's elements sorted in lexicographical order.
func (set Set) ToSlice() []string {
	return SortedSet(set).ToSlice()
}
