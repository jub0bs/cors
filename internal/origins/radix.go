package origins

import (
	"iter"
	"math"
	"slices"
	"strconv"
	"strings"
)

// A Tree is a radix tree that represents a set of Web origins.
// The zero value corresponds to an empty tree.
//
// A Tree can be grown by inserting values of type [Pattern] in it, and
// a Tree can be queried about whether it contains some [Origin] value.
type Tree struct {
	root node
}

// NewTree returns a new tree in which all of ps have been inserted.
func NewTree(ps ...*Pattern) Tree {
	// Sorting patterns with (*Pattern).Compare before inserting them in an
	// empty tree guarantees that the resulting tree be free of redundant
	// elements, thereby obviating any need to subsequently prune the tree.
	slices.SortFunc(ps, (*Pattern).Compare)
	// Avoid inserting identical patterns multiple times.
	ps = slices.CompactFunc(ps, (*Pattern).Equal)
	var t Tree
	if len(ps) > 0 {
		// Inserting the first pattern is easy, since t is empty.
		p := ps[0]
		host, wildcardSubs := strings.CutPrefix(p.HostPattern, subdomainWildcard)
		t.root.suf = host
		t.root.add(p.Scheme, p.Port, wildcardSubs)
		// Now deal with the remaining patterns.
		ps = ps[1:]
	}
	for _, p := range ps {
		host, wildcardSubs := strings.CutPrefix(p.HostPattern, subdomainWildcard)
		n := &t.root
		for {
			prefixOfNSuf, prefixOfHost, suf := splitAtCommonSuffix(n.suf, host)
			label1, ok1 := lastByte(prefixOfNSuf)
			label2, ok2 := lastByte(prefixOfHost)
			if !ok1 {
				if !ok2 { // n.suf == host
					n.add(p.Scheme, p.Port, wildcardSubs)
					break
				} else { // n.suf is a strict suffix of host.
					// Example:
					// - n.suf: kin
					// - host: akin
					if n.contains(p.Scheme, p.Port, true) {
						// Avoid redundancy.
						break
					}
					// Look for an edge labeled label2 stemming from n.
					i, ok := slices.BinarySearch(n.edges, label2)
					if !ok { // No such edge found.
						// Create one leading to the new child:
						//
						//  kin - a (child)
						//
						child := node{suf: prefixOfHost}
						child.add(p.Scheme, p.Port, wildcardSubs)
						n.insertEdge(i, label2, &child)
						break
					}
					// Edge found. Keep going.
					host = prefixOfHost
					n = n.children[i]
					continue
				}
			} else {
				// If !ok2, host is a strict suffix of n.suf.
				// Example:
				// - n.suf: akin
				// - host:   kin
				// However, because of how we sort patterns before inserting
				// them into the tree, this case cannot occur.
				//
				// If ok2, neither n.suf nor host is a suffix (strict or not)
				// of the other. Moreover, because of how we sort patterns
				// before inserting them into the tree, we know that
				// label1 < label2.
				// Example:
				// - n.suf:    akin
				// - host:  pumpkin
				// Perform a two-way split of n:
				//
				//   kin - a (child1)
				//      \
				//       pump (child2)
				//
				child1 := *n
				child1.suf = prefixOfNSuf
				child2 := node{suf: prefixOfHost}
				child2.add(p.Scheme, p.Port, wildcardSubs)
				*n = node{suf: suf}
				n.insertEdge(0, label1, &child1)
				n.insertEdge(1, label2, &child2)
				break
			}
		}
	}
	return t
}

// IsEmpty reports whether t is empty.
func (t *Tree) IsEmpty() bool {
	return t.root.isEmpty()
}

// Contains reports whether t contains o.
func (t *Tree) Contains(o *Origin) bool {
	host := o.Host
	n := &t.root
	for {
		prefixOfHost, _, suf := splitAtCommonSuffix(host, n.suf)
		if len(suf) != len(n.suf) {
			// n.suf is NOT a suffix of host. Example:
			// - n.suf: akin
			// - host:   kin
			return false
		}
		// n.suf is a suffix of host.

		label, ok := lastByte(prefixOfHost)
		if !ok {
			// n.suf == host
			return n.contains(o.Scheme, o.Port, false)
		}

		// host is a strict suffix of n.suf.
		// Example:
		// - n.suf: .kin
		// - host: a.kin

		// Check whether n contains port for wildcard subs.
		if n.contains(o.Scheme, o.Port, true) {
			return true
		}

		// Look for an edge labeled 'a' in n.
		i, found := slices.BinarySearch(n.edges, label)
		if !found {
			return false
		}
		host = prefixOfHost
		n = n.children[i]
	}
}

func lastByte(str string) (byte, bool) {
	if str == "" {
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
// The order is unspecified; however, the order is stable, in the sense that
// different calls to t.Elems systematically yield the same elements in the
// same order.
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
	children []*node
	// schemes are the schemes of this node.
	schemes []string
	// ports are the ports associated to this node's schemes ("parallels"
	// schemes slice).
	ports [][]int
}

func (n *node) add(scheme string, port int, wildcardSubs bool) {
	arbitraryPort := arbitraryPort // shadows package-level constant
	if wildcardSubs {
		port, arbitraryPort = offset(port, arbitraryPort)
	}
	i, found := slices.BinarySearch(n.schemes, scheme)
	if !found {
		n.schemes = slices.Insert(n.schemes, i, scheme)
		n.ports = slices.Insert(n.ports, i, []int{port})
		return
	}
	ports := n.ports[i]
	_, found = slices.BinarySearch(ports, arbitraryPort)
	if found {
		// Avoid redundancy.
		return
	}
	// At this stage, because of how we sort patterns before inserting them
	// into the tree, port is guaranteed to be greater than all elements of
	// ports; therefore, appending it to ports keeps the latter sorted in
	// increasing order.
	n.ports[i] = append(ports, port)
}

func offset(port, arbitraryPort int) (int, int) {
	return port - portOffset, arbitraryPort - portOffset
}

// an offset used for storing ports corresponding to wildcard subs
const portOffset = math.MaxUint16 + 2

func (n *node) isEmpty() bool {
	return n.schemes == nil && n.children == nil
}

func (n *node) contains(scheme string, port int, wildcardSubs bool) (found bool) {
	arbitraryPort := arbitraryPort // shadows package-level constant
	if wildcardSubs {
		port, arbitraryPort = offset(port, arbitraryPort)
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
	_, found = slices.BinarySearch(ports, arbitraryPort)
	return
}

// insertEdge inserts an edge labeled label and leading to child at index i
// in n.edges.
// Precondition: i <= len(n.edges)
func (n *node) insertEdge(i int, label byte, child *node) {
	n.edges = slices.Insert(n.edges, i, label)
	n.children = slices.Insert(n.children, i, child)
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
			if port < arbitraryPort {
				maybeWildcard = subdomainWildcard
				port += portOffset
			}
			var s string
			switch port {
			case absentPort:
				s = scheme + schemeHostSep + maybeWildcard + suf
			case arbitraryPort:
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
