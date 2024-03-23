// Package radix provides an implementation of a specialized radix tree.
// The implementation draws heavy inspiration from
// https://github.com/armon/go-radix.
package radix

import (
	"strings"

	"github.com/jub0bs/cors/internal/util"
)

// A Tree is radix tree whose edges are each labeled by a byte,
// and whose conceptual leaf nodes each contain a set of ints.
// The zero value of a Tree is an empty tree.
type Tree struct {
	root node
}

// Insert inserts v in the tree according to keyPattern.
// The key pattern is processed from right to left.
// A leading * byte (0x2a) denotes a wildcard for any non-empty byte sequence.
// A non-leading * has no special meaning and is treated as any other byte.
// Sentinel value -1 represents a wildcard value that subsumes all others.
func (t *Tree) Insert(keyPattern string, v int) {
	var wildcardPattern bool
	if strings.HasPrefix(keyPattern, "*") {
		wildcardPattern = true
		keyPattern = keyPattern[1:]
	}
	var parent *node
	n := &t.root
	search := keyPattern
	for {
		if len(search) == 0 {
			n.add(v, wildcardPattern)
			return
		}
		if n.wildcardSet.Contains(v) { // nothing more to do
			return
		}
		parent = n
		n = n.edges[lastByteIn(search)]
		if n == nil { // no matching edge found; create one
			child := &node{suffix: search}
			child.add(v, wildcardPattern)
			parent.insertEdge(lastByteIn(search), child)
			return
		}

		// matching edge found
		suffixLen := lengthOfCommonSuffix(search, n.suffix)
		if suffixLen == len(n.suffix) { // n.suffix is a suffix of search
			search, _ = splitRight(search, suffixLen)
			continue
		}

		// n.suffix is NOT a suffix of search; split the node
		child := new(node)
		_, child.suffix = splitRight(search, suffixLen)
		parent.insertEdge(lastByteIn(search), child)

		// restore the existing node
		byteBeforeSuffix := n.suffix[len(n.suffix)-1-suffixLen]
		child.insertEdge(byteBeforeSuffix, n)
		if len(search) == suffixLen { // search is a suffix of n.suffix
			n.suffix, _ = splitRight(n.suffix, suffixLen)
			child.add(v, wildcardPattern)
			return
		}
		// search is NOT a suffix of n.suffix
		n.suffix, _ = splitRight(n.suffix, suffixLen)
		search, _ = splitRight(search, suffixLen)
		grandChild := &node{suffix: search}
		grandChild.add(v, wildcardPattern)
		child.insertEdge(lastByteIn(search), grandChild)
	}
}

// Contains reports whether t contains key-value pair (k,v).
func (t *Tree) Contains(k string, v int) bool {
	n := &t.root
	search := k
	for {
		if len(search) == 0 {
			return n.set.Contains(v) ||
				n.set.Contains(WildcardElem)
		}

		// search is not empty; check wildcard edge
		if n.wildcardSet.Contains(v) ||
			n.wildcardSet.Contains(WildcardElem) { // nothing more to check
			return true
		}

		// try regular edges
		n = n.edges[lastByteIn(search)]
		if n == nil {
			return false
		}

		if !strings.HasSuffix(search, n.suffix) {
			return false
		}
		search, _ = splitRight(search, len(n.suffix))
	}
}

// assumes s is non-empty
func lastByteIn(str string) byte {
	return str[len(str)-1]
}

// assumes len(s) >= length
func splitRight(str string, length int) (start, end string) {
	j := len(str) - length
	return str[:j], str[j:]
}

// WildcardElem is a sentinel value that subsumes all others.
const WildcardElem = -1

// A node represents a regular node
// (i.e. a node that does not stem from a wildcard edge)
// of a Tree.
type node struct {
	// suffix of this node (not restricted to ASCII or even valid UTF-8)
	suffix string
	// edges to children of this node
	edges edges
	// values in this node
	set util.Set[int]
	// values in the "conceptual" child node down the wildcard edge
	// that stems from this node
	wildcardSet util.Set[int]
}

func (n *node) add(elem int, wildcardPattern bool) {
	var set *util.Set[int]
	if wildcardPattern {
		set = &n.wildcardSet
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

func lengthOfCommonSuffix(s1, s2 string) int {
	l1 := len(s1) - 1
	l2 := len(s2) - 1
	l := min(l1, l2)
	var i int
	for ; i <= l; i++ {
		if s1[l1-i] != s2[l2-i] {
			break
		}
	}
	return i
}
