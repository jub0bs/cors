// Package radix provides an implementation of a specialized radix tree.
// The implementation draws heavy inspiration from
// https://github.com/armon/go-radix.
package radix

import "github.com/jub0bs/cors/internal/util"

// A Tree is radix tree whose edges are each labeled by a byte,
// and whose conceptual leaf nodes each contain a set of ints.
// The zero value of a Tree is an empty tree.
type Tree struct {
	root node
}

// Insert inserts v in the tree according to keyPattern.
// A leading * byte (0x2a) denotes a wildcard for any non-empty byte sequence.
// A non-leading * has no special meaning and is treated as any other byte.
// Sentinel value -1 represents a wildcard value that subsumes all others.
func (t *Tree) Insert(keyPattern string, v int) {
	var hasLeadingAsterisk bool
	// check for a leading asterisk
	if b, rest, ok := splitAfterFirstByte(keyPattern); ok && b == '*' {
		hasLeadingAsterisk = true
		keyPattern = rest
	}
	var parent *node
	n := &t.root
	// The key pattern is processed from right to left.
	search := keyPattern
	for {
		label, ok := lastByte(search)
		if !ok {
			n.add(v, hasLeadingAsterisk)
			return
		}
		if n.wSet.Contains(v) {
			return
		}
		parent = n
		n = n.edges[label]
		if n == nil { // no matching edge found; create one
			child := &node{suf: search}
			child.add(v, hasLeadingAsterisk)
			parent.insertEdge(label, child)
			return
		}

		// matching edge found
		searchPrefix, prefixOfNSuf, suf := splitAtCommonSuffix(search, n.suf)
		if len(suf) == len(n.suf) { // n.suf is a suffix of search
			search = searchPrefix
			continue
		}

		// n.suf is NOT a suffix of search; split the node
		child := &node{suf: suf}
		parent.insertEdge(label, child)

		// Restore the existing node.
		// Because n.suf is not a suffix of search,
		// prefixOfNSuf is necessarily non-empty.
		byteBeforeSuffix, _ := lastByte(prefixOfNSuf)
		child.insertEdge(byteBeforeSuffix, n)
		if len(suf) == len(search) { // search is a suffix of n.suf
			n.suf = prefixOfNSuf
			child.add(v, hasLeadingAsterisk)
			return
		}

		// search is NOT a suffix of n.suf
		n.suf = prefixOfNSuf
		// Because search is NOT a suffix of n.suf,
		// searchPrefix is necessarily non-empty.
		label, _ = lastByte(searchPrefix)
		search = searchPrefix
		grandChild := &node{suf: search}
		grandChild.add(v, hasLeadingAsterisk)
		child.insertEdge(label, grandChild)
	}
}

// Contains reports whether t contains key-value pair (k,v).
func (t *Tree) Contains(k string, v int) bool {
	n := &t.root
	search := k
	for {
		label, ok := lastByte(search)
		if !ok {
			return n.set.Contains(v) || n.set.Contains(WildcardElem)
		}

		// search is not empty; check wildcard edge
		if n.wSet.Contains(v) || n.wSet.Contains(WildcardElem) {
			return true
		}

		// try regular edges
		n = n.edges[label]
		if n == nil {
			return false
		}

		searchPrefix, _, suf := splitAtCommonSuffix(search, n.suf)
		if len(suf) != len(n.suf) { // n.suf is NOT a suffix of search
			return false
		}
		// n.suf is a suffix of search
		search = searchPrefix
	}
}

func splitAfterFirstByte(str string) (byte, string, bool) {
	if len(str) == 0 {
		return 0, str, false
	}
	return str[0], str[1:], true
}

func lastByte(str string) (byte, bool) {
	if len(str) == 0 {
		return 0, false
	}
	return str[len(str)-1], true
}

// splitAtCommonSuffix finds the longest suffix common to a and b and returns
// a and b both trimmed of that suffix along with the suffix itself.
func splitAtCommonSuffix(a, b string) (string, string, string) {
	s, l := a, b // s for short, l for long
	if len(l) < len(s) {
		s, l = l, s
	}
	l = l[len(l)-len(s):]
	_ = l[:len(s)] // hoist bounds checks on l out of the loop
	i := len(s) - 1
	for ; 0 <= i && s[i] == l[i]; i-- {
		// deliberately empty body
	}
	i++
	return a[:len(a)-len(s)+i], b[:len(b)-len(s)+i], s[i:]
}

// WildcardElem is a sentinel value that subsumes all others.
const WildcardElem = -1

// A node represents a regular node
// (i.e. a node that does not stem from a wildcard edge)
// of a Tree.
type node struct {
	// suf of this node (not restricted to ASCII or even valid UTF-8)
	suf string
	// edges to children of this node
	edges edges
	// values in this node
	set util.Set[int]
	// values in the "conceptual" child node down the wildcard edge
	// that stems from this node
	wSet util.Set[int]
}

func (n *node) add(elem int, toWildcardSet bool) {
	var set *util.Set[int]
	if toWildcardSet {
		set = &n.wSet
	} else {
		set = &n.set
	}
	if elem == WildcardElem {
		*set = wildcardSingleton
		return
	}
	if *set == nil {
		*set = util.NewSet(elem)
		return
	}
	if set.Contains(WildcardElem) { // nothing to do
		return
	}
	set.Add(elem)
}

var wildcardSingleton = util.NewSet(WildcardElem)

func (n *node) insertEdge(label byte, child *node) {
	if n.edges == nil {
		n.edges = edges{label: child}
		return
	}
	n.edges[label] = child
}

type edges = map[byte]*node
