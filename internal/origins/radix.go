package origins

import (
	"math"
	"strconv"
)

// A Tree is a radix tree that represents a set of (host, port) pairs.
// The zero value of Tree is an empty tree.
type Tree struct {
	root node
}

// Insert inserts port in t according to hostPattern,
// which is processed from right to left.
// A leading * byte (0x2a) denotes a wildcard for any non-empty byte sequence.
// A non-leading * has no special meaning and is treated as any other byte.
func (t *Tree) Insert(hostPattern string, port int) {
	var wildcardSubs bool
	if b, rest, ok := splitAfterFirstByte(hostPattern); ok && b == '*' {
		wildcardSubs = true
		hostPattern = rest
	}
	n := &t.root
	s := hostPattern
	for {
		labelToChild, ok := lastByte(s)
		if !ok { // s is empty
			n.add(port, wildcardSubs)
			return
		}
		if n.contains(port, true) {
			return
		}
		child := n.edges[labelToChild]
		if child == nil { // No matching edge found; create one.
			child = &node{suf: s}
			child.add(port, wildcardSubs)
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
			child.add(port, wildcardSubs)
			return
		}

		// Add a second grandchild in child.
		grandChild2 := &node{suf: prefixOfS}
		grandChild2.add(port, wildcardSubs)
		child.upsertEdge(labelToGrandChild2, grandChild2)
	}
}

// Contains reports whether t contains key-value pair (host, port).
func (t Tree) Contains(host string, port int) bool {
	n := &t.root
	for {
		label, ok := lastByte(host)
		if !ok {
			return n.contains(port, false)
		}

		// host is not empty;
		// check whether n contains port for wildcard subs
		if n.contains(port, true) {
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
func (t Tree) Elems(dst *[]string, prefix string) {
	t.root.elems(dst, prefix, "")
}

// A node represents a node of a Tree.
type node struct {
	// suf of this node (not restricted to ASCII or even valid UTF-8)
	suf string
	// ports (both for an exact match and for wildcard subs) in this node
	ports ports
	// edges to children of this node
	edges edges
}

type ports = map[int]struct{}

const (
	// a sentinel value that subsumes all other port numbers
	wildcardPort = math.MaxUint16 + 1
	// an offset used for storing ports corresponding to wildcard subs
	portOffset = wildcardPort + 1
)

func (n *node) add(port int, wildcardSubs bool) {
	wildcardPort := wildcardPort // shadows package-level constant
	if wildcardSubs {
		port -= portOffset
		wildcardPort -= portOffset
	}
	if n.contains(wildcardPort, wildcardSubs) { // nothing to do
		return
	}
	if n.ports == nil {
		n.ports = make(ports)
	}
	n.ports[port] = struct{}{}
}

func (n node) contains(port int, wildcardSubs bool) (found bool) {
	wildcardPort := wildcardPort // shadows package-level constant
	if wildcardSubs {
		port -= portOffset
		wildcardPort -= portOffset
	}
	_, found = n.ports[port]
	if !found {
		_, found = n.ports[wildcardPort]
	}
	return found
}

func (n *node) upsertEdge(label byte, child *node) {
	if n.edges == nil {
		n.edges = edges{label: child}
		return
	}
	n.edges[label] = child
}

type edges = map[byte]*node

// elems adds textual representations of n's elements to dst,
// using prefix as prefix and using suf as a base suffix.
func (n node) elems(dst *[]string, prefix, suf string) {
	suf = n.suf + suf
	for port := range n.ports {
		prefix := prefix // shadows parameter
		if port < 0 {
			prefix += subdomainWildcard
			port += portOffset
		}
		s := suf
		switch port {
		case 0: // deliberately empty case
		case wildcardPort:
			s += ":" + portWildcard
		default:
			s += ":" + strconv.Itoa(port)
		}
		*dst = append(*dst, prefix+s)
	}
	for _, child := range n.edges {
		child.elems(dst, prefix, suf)
	}
}
