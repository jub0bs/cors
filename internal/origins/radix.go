package origins

import (
	"iter"
	"slices"
	"strconv"
	"strings"
)

// A Tree is a radix tree that represents a set of Web origins.
// The zero value of Tree corresponds to an empty tree.
type Tree struct {
	root node
}

// IsEmpty reports whether t is empty.
func (t *Tree) IsEmpty() bool {
	return t.root.schemes == nil && t.root.children == nil
}

// Insert inserts p in t.
func (t *Tree) Insert(p *Pattern) {
	s := p.HostPattern // non-empty by construction
	s, wildcardSubs := strings.CutPrefix(s, "*")
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
		i, found := slices.BinarySearch(n.edges, labelToChild)
		if !found { // No matching edge found; create one.
			child := node{suf: s}
			child.add(p.Scheme, p.Port, wildcardSubs)
			n.upsertEdge(labelToChild, child)
			return
		}
		child := &n.children[i]

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
		// After splitting:  child' -- grandChild
		//
		// ... or perhaps    child' -- grandChild1
		//                      \
		//                       grandChild2

		// Create a first grandchild on the basis of the current child.
		grandChild1 := node{
			suf:      prefixOfChildSuf,
			edges:    child.edges,
			children: child.children,
			schemes:  child.schemes,
			ports:    child.ports,
		}

		// Replace child in n.
		child = n.upsertEdge(labelToChild, node{suf: suf})

		// Add a first grandchild in child.
		child.upsertEdge(labelToGrandChild1, grandChild1)
		labelToGrandChild2, ok := lastByte(prefixOfS)
		if !ok {
			child.add(p.Scheme, p.Port, wildcardSubs)
			return
		}

		// Add a second grandchild in child.
		grandChild2 := node{suf: prefixOfS}
		grandChild2.add(p.Scheme, p.Port, wildcardSubs)
		child.upsertEdge(labelToGrandChild2, grandChild2)
		return
	}
}

// Contains reports whether t contains o.
func (t *Tree) Contains(o *Origin) bool {
	host := o.Host
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

		i, found := slices.BinarySearch(n.edges, label)
		if !found {
			return false
		}
		n = &n.children[i]

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
	i := len(s)
	l = l[len(l)-i:]
	_ = l[:i] // hoist bounds checks on l out of the loop
	for ; 0 < i && s[i-1] == l[i-1]; i-- {
		// deliberately empty body
	}
	return a[:len(a)-len(s)+i], b[:len(b)-len(s)+i], s[i:]
}

// Elems returns an iterator over textual representations of t's elements.
// The order is unspecified. However, the order is stable: different calls to
// t.Elems always yield the same elements in the same order.
func (t *Tree) Elems() iter.Seq[string] {
	return func(yield func(string) bool) {
		t.root.elems("", yield)
	}
}

// A node represents a node of a Tree.
// Invariants:
//   - len(edges) == len(children)
//   - len(schemes) == len(ports)
type node struct {
	// suf is the suffix of this node (not restricted to ASCII or even valid
	// UTF-8).
	suf string
	// edges are the edges to children of this node.
	edges []byte
	// children are the children of this node ("parallels" edges slice).
	// Using []*node is tempting because it is expedient, but using []node is
	// more performant (because it involves one fewer lever of indirection) at
	// the cost of some gymnastics.
	children []node
	// schemes are the schemes of this node.
	schemes []string
	// ports are the ports associated to this node's schemes ("parallels"
	// schemes slice).
	ports [][]int
}

func (n *node) add(scheme string, port int, wildcardSubs bool) {
	wildcardPort := wildcardPort // shadows package-level constant
	if wildcardSubs {
		port -= portOffset
		wildcardPort -= portOffset
	}
	if n.contains(scheme, port, wildcardSubs) {
		return
	}
	i, found := slices.BinarySearch(n.schemes, scheme)
	if !found {
		n.schemes = slices.Insert(n.schemes, i, scheme)
		n.ports = slices.Insert(n.ports, i, []int{port})
		return
	}
	ports := n.ports[i]
	if port == wildcardPort {
		ports = deleteSameSign(ports, port)
	}
	ports = append(ports, port)
	slices.Sort(ports)
	n.ports[i] = ports
}

// an offset used for storing ports corresponding to wildcard subs
const portOffset = wildcardPort + 1

// deleteSameSign, if v is negative, removes all the negative values from s;
// otherwise, it removes all the non-negative values from s.
// Precondition: s is sorted in increasing order.
func deleteSameSign(s []int, v int) []int {
	i, _ := slices.BinarySearch(s, 0)
	if v < 0 {
		return s[i:]
	}
	return s[:i]
}

func (n *node) contains(scheme string, port int, wildcardSubs bool) (found bool) {
	wildcardPort := wildcardPort // shadows package-level constant
	if wildcardSubs {
		port -= portOffset
		wildcardPort -= portOffset
	}
	i, found := slices.BinarySearch(n.schemes, scheme)
	if !found {
		return
	}
	ports := n.ports[i]
	_, found = slices.BinarySearch(ports, port)
	if found {
		return
	}
	_, found = slices.BinarySearch(ports, wildcardPort)
	return
}

// upsertEdge updates or inserts child in n down an edge labeled by label
// and returns a pointer to the corresponding child in n.
func (n *node) upsertEdge(label byte, child node) *node {
	i, found := slices.BinarySearch(n.edges, label)
	if !found {
		n.edges = slices.Insert(n.edges, i, label)
		n.children = slices.Insert(n.children, i, child)
		return &n.children[i]
	}
	n.children[i] = child
	return &n.children[i]
}

// elems reports whether f(x) is true for the textual representation
// (using suf as base suffix) of every element x in n.
func (n *node) elems(suf string, f func(string) bool) bool {
	suf = n.suf + suf
	var ( // Hoist bounds checks out of the outer loop.
		nSchemes = n.schemes
		nPorts   = n.ports[:len(nSchemes)]
	)
	for i, ports := range nPorts {
		scheme := nSchemes[i]
		for _, port := range ports {
			var maybeWildcard string
			if port < 0 {
				maybeWildcard = subdomainWildcard
				port += portOffset
			}
			var s string
			switch port {
			case 0:
				s = scheme + schemeHostSep + maybeWildcard + suf
			case wildcardPort:
				s = scheme + schemeHostSep + maybeWildcard + suf + string(hostPortSep) + portWildcard
			default:
				s = scheme + schemeHostSep + maybeWildcard + suf + string(hostPortSep) + strconv.Itoa(port)
			}
			if !f(s) {
				return false
			}
		}
	}
	children := n.children // Hoist bounds checks out of the loop.
	for i := range children {
		if !children[i].elems(suf, f) {
			return false
		}
	}
	return true
}
