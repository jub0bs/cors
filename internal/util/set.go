package util

// A Set represents a mathematical set of ints or strings.
type Set[E int | string] map[E]struct{}

// NewSet returns a Set that contains first and all elements of rest,
// but no other elements.
func NewSet[E int | string](first E, rest ...E) Set[E] {
	set := make(Set[E], 1+len(rest))
	set.Add(first)
	for _, e := range rest {
		set.Add(e)
	}
	return set
}

// Add adds e to s.
func (s Set[E]) Add(e E) {
	s[e] = struct{}{}
}

// Contains returns true if e is an element of s, and false otherwise.
func (s Set[E]) Contains(e E) bool {
	_, found := s[e]
	return found
}
