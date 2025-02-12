package origins

import "strconv"

// A Tree is radix tree whose edges are each labeled by a byte,
// and whose conceptual leaf nodes each contain two sets of ports.
// The zero value of a Tree is an empty tree.
//
// The implementation draws heavy inspiration from
// https://github.com/armon/go-radix.
type Tree struct {
	root node
}

// Insert inserts port in the tree according to hostPattern.
// A leading * byte (0x2a) denotes a wildcard for any non-empty byte sequence.
// A non-leading * has no special meaning and is treated as any other byte.
func (t *Tree) Insert(hostPattern string, port int) {
	var hasLeadingAsterisk bool
	// check for a leading asterisk
	if b, rest, ok := splitAfterFirstByte(hostPattern); ok && b == '*' {
		hasLeadingAsterisk = true
		hostPattern = rest
	}
	n := &t.root
	// The host pattern is processed from right to left.
	s := hostPattern
	for {
		labelToChild, ok := lastByte(s)
		if !ok { // s is empty
			n.add(port, hasLeadingAsterisk)
			return
		}
		if n.wSet.Contains(port) {
			return
		}
		child := n.edges[labelToChild]
		if child == nil { // No matching edge found; create one.
			child = &node{suf: s}
			child.add(port, hasLeadingAsterisk)
			n.upsertEdge(labelToChild, child)
			return
		}

		prefixOfS, prefixOfChildSuf, suf := splitAtCommonSuffix(s, child.suf)
		labelToGrandChild1, ok := lastByte(prefixOfChildSuf)
		if !ok { // child.suf is a suffix of s
			s = prefixOfS
			n = child
			continue
		}
		// child.suf is NOT a suffix of s; we need to split child.
		//
		// Before splitting: child
		//
		// After splitting:  child' -- grandChild1
		//
		// ... or perhaps    child' -- grandChild1
		//                      \
		//                       grandChild2

		// Create a first grandchild on the basis of the current child.
		grandChild1 := child
		grandChild1.suf = prefixOfChildSuf

		// Replace child in n.
		child = &node{suf: suf}
		n.upsertEdge(labelToChild, child)

		// Add a first grandchild in child.
		child.upsertEdge(labelToGrandChild1, grandChild1)
		labelToGrandChild2, ok := lastByte(prefixOfS)
		if !ok {
			child.add(port, hasLeadingAsterisk)
			return
		}

		// Add a second grandchild in child.
		grandChild2 := &node{suf: prefixOfS}
		grandChild2.add(port, hasLeadingAsterisk)
		child.upsertEdge(labelToGrandChild2, grandChild2)
	}
}

// Contains reports whether t contains key-value pair (host,port).
func (t *Tree) Contains(host string, port int) bool {
	n := &t.root
	for {
		label, ok := lastByte(host)
		if !ok {
			return n.set.Contains(port)
		}

		// host is not empty; check wildcard edge
		if n.wSet.Contains(port) {
			return true
		}

		// try regular edges
		n = n.edges[label]
		if n == nil {
			return false
		}

		prefixOfHost, _, suf := splitAtCommonSuffix(host, n.suf)
		if len(suf) != len(n.suf) { // n.suf is NOT a suffix of host
			return false
		}
		// n.suf is a suffix of host
		host = prefixOfHost
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

// Elems returns a slice containing textual representations of t's elements.
func (t *Tree) Elems(dst *[]string, prefix string) {
	t.root.Elems(dst, prefix, "")
}

// A node represents a regular node
// (i.e. a node that does not stem from a wildcard edge)
// of a Tree.
type node struct {
	// suf of this node (not restricted to ASCII or even valid UTF-8)
	suf string
	// edges to children of this node
	edges edges
	// values in this node
	set PortSet
	// values in the "conceptual" child node down the wildcard edge
	// that stems from this node
	wSet PortSet
}

func (n *node) add(port int, wildcardSubs bool) {
	if wildcardSubs {
		n.wSet.Add(port)
	} else {
		n.set.Add(port)
	}
}

func (n *node) upsertEdge(label byte, child *node) {
	if n.edges == nil {
		n.edges = edges{label: child}
		return
	}
	n.edges[label] = child
}

type edges = map[byte]*node

// Elems adds textual representations of n's elements to dst,
// using suf as a base suffix.
func (n *node) Elems(dst *[]string, prefix, suf string) {
	suf = n.suf + suf
	for port := range n.set {
		emit(dst, prefix, suf, port)
	}
	for port := range n.wSet {
		emit(dst, prefix+subdomainWildcard, suf, port)
	}
	for _, child := range n.edges {
		child.Elems(dst, prefix, suf)
	}
}

func emit(dst *[]string, prefix, suf string, port int) {
	var s string
	switch port {
	case wildcardPort:
		s = suf + ":" + portWildcard
	case 0:
		s = suf
	default:
		s = suf + ":" + strconv.Itoa(port)
	}
	*dst = append(*dst, prefix+s)
}
