package origins

import (
	"slices"

	"github.com/jub0bs/cors/internal/origins/radix"
)

// A Corpus represents a set of allowed (tuple) [Web origins].
// The keys in this map correspond to origin schemes.
//
// [Web origins]: https://developer.mozilla.org/en-US/docs/Glossary/Origin
type Corpus map[string]radix.Tree

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

// Elems returns a slice containing textual representations of c's elements.
func (c Corpus) Elems() []string {
	var res []string
	schemes := make([]string, 0, len(c))
	for scheme := range c {
		schemes = append(schemes, scheme)
	}
	slices.Sort(schemes)
	for _, scheme := range schemes {
		tree := c[scheme]
		elems := tree.Elems()
		for i := range elems {
			elems[i] = scheme + "://" + elems[i]
		}
		res = append(res, elems...)
	}
	return res
}
