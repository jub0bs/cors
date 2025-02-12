package origins

import (
	"math"
	"slices"
	"strconv"
)

// A Tree is a radix tree that represents a set of Web origins.
// The zero value of Tree is an empty tree.
type Tree struct {
	root node
}

// Insert inserts p in t.
func (t *Tree) Insert(p *Pattern) {
	s := p.HostPattern.Value // non-empty by construction
	var wildcardSubs bool
	if s[0] == '*' {
		wildcardSubs = true
		s = s[1:]
	}
	n := &t.root
	for {
		labelToChild, ok := lastByte(s)
		if !ok { // s is empty
			n.add(p.Scheme, p.Port, wildcardSubs)
			return
		}
		if n.contains(p.Scheme, p.Port, true) {
			return
		}
		child := n.edges[labelToChild]
		if child == nil { // No matching edge found; create one.
			child = &node{suf: s}
			child.add(p.Scheme, p.Port, wildcardSubs)
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
			child.add(p.Scheme, p.Port, wildcardSubs)
			return
		}

		// Add a second grandchild in child.
		grandChild2 := &node{suf: prefixOfS}
		grandChild2.add(p.Scheme, p.Port, wildcardSubs)
		child.upsertEdge(labelToGrandChild2, grandChild2)
	}
}

// Contains reports whether t contains o.
func (t *Tree) Contains(o *Origin) bool {
	host := o.Host.Value
	n := &t.root
	for {
		label, ok := lastByte(host)
		if !ok {
			return n.contains(o.Scheme, o.Port, false)
		}

		// host is not empty;
		// check whether n contains port for wildcard subs.
		if n.contains(o.Scheme, o.Port, true) {
			return true
		}

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
func (t *Tree) Elems() []string {
	var res []string
	t.root.elems(&res, "")
	slices.Sort(res)
	return res
}

// A node represents a node of a Tree.
type node struct {
	// suf of this node (not restricted to ASCII or even valid UTF-8)
	suf string
	// edges to children of this node
	edges edges
	// ports (both for an exact match and for wildcard subs) in this node
	portSchemes portSchemes
}

type edges = map[byte]*node

type portSchemes = map[portScheme]struct{}

type portScheme struct {
	port   int
	scheme string
}

const (
	// a sentinel value that subsumes all other port numbers
	wildcardPort = math.MaxUint16 + 1
	// an offset used for storing ports corresponding to wildcard subs
	portOffset = wildcardPort + 1
)

func (n *node) add(scheme string, port int, wildcardSubs bool) {
	wildcardPort := wildcardPort // shadows package-level constant
	if wildcardSubs {
		port -= portOffset
		wildcardPort -= portOffset
	}
	if n.contains(scheme, wildcardPort, wildcardSubs) { // nothing to do
		return
	}
	if n.portSchemes == nil {
		n.portSchemes = make(portSchemes)
	}
	n.portSchemes[portScheme{port, scheme}] = struct{}{}
}

func (n *node) contains(scheme string, port int, wildcardSubs bool) (found bool) {
	wildcardPort := wildcardPort // shadows package-level constant
	if wildcardSubs {
		port -= portOffset
		wildcardPort -= portOffset
	}
	_, found = n.portSchemes[portScheme{port, scheme}]
	if !found {
		_, found = n.portSchemes[portScheme{wildcardPort, scheme}]
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

// elems adds textual representations of n's elements
// (using suf as base suffix) to dst.
func (n *node) elems(dst *[]string, suf string) {
	suf = n.suf + suf
	for pair := range n.portSchemes {
		prefix := pair.scheme + schemeHostSep
		if pair.port < 0 {
			prefix += subdomainWildcard
			pair.port += portOffset
		}
		s := prefix + suf
		switch pair.port {
		case 0: // deliberately empty case
		case wildcardPort:
			s += ":" + portWildcard
		default:
			s += ":" + strconv.Itoa(pair.port)
		}
		*dst = append(*dst, s)
	}
	for _, child := range n.edges {
		child.elems(dst, suf)
	}
}
