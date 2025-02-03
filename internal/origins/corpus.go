package origins

import "slices"

// A Corpus represents a set of allowed (tuple) [Web origins].
// The keys in this map correspond to origin schemes.
//
// [Web origins]: https://developer.mozilla.org/en-US/docs/Glossary/Origin
type Corpus map[string]Tree

// Add augments c with all Web origins encompassed by pattern.
func (c Corpus) Add(pattern *Pattern) {
	tree := c[pattern.Scheme]
	tree.Insert(pattern.Value, pattern.Port)
	c[pattern.Scheme] = tree
}

// Contains reports whether c contains origin o.
func (c Corpus) Contains(o *Origin) bool {
	tree, found := c[o.Scheme]
	return found && tree.Contains(o.Value, o.Port)
}

// Elems returns a sorted slice of textual representations of c's elements.
func (c Corpus) Elems() (res []string) {
	for scheme, tree := range c {
		tree.Elems(&res, scheme+schemeHostSep)
	}
	slices.Sort(res)
	return
}
