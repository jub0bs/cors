package origins

import (
	"iter"
	"math"
	"slices"
	"strconv"
	"strings"
)

// A Tree is a specialized radix tree that represents a (possibly infinite) set
// of Web origins. Once built, a Tree is read-only. The zero value corresponds
// to an empty tree.
type Tree struct {
	root *node
}

// NewTree returns a new tree in which all of ps (and no other origin patterns)
// have been inserted.
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
		host, arbitrarySubs := strings.CutPrefix(p.HostPattern, subdomainWildcard)
		t.root = &node{suf: host}
		t.root.add(p.Scheme, p.Port, arbitrarySubs)
		// Now deal with the remaining patterns.
		ps = ps[1:]
	}
	for _, p := range ps {
		host, arbitrarySubs := strings.CutPrefix(p.HostPattern, subdomainWildcard)
		n := t.root
		for {
			prefixOfNSuf, prefixOfHost, suf := splitAtCommonSuffix(n.suf, host)
			label1, ok1 := last([]byte(prefixOfNSuf))
			label2, ok2 := last([]byte(prefixOfHost))
			if !ok1 {
				if !ok2 {
					// n.suf and host are equal.
					n.add(p.Scheme, p.Port, arbitrarySubs)
					break
				} else {
					// n.suf is a strict suffix of host.
					// Example:
					//  - n.suf:     kin
					//  - host:  pumpkin
					if n.contains(p.Scheme, p.Port, true) {
						// Inserting p in t would cause redundancy. Let's not.
						break
					}
					// Look for an edge labeled label2 stemming from n.
					// Because of how we sort ps before inserting them into t,
					// if label2 appears in n.edges, it has to be at the end.
					if lastLabel, ok := last(n.edges); !ok || lastLabel != label2 {
						// No such edge was found.
						// Create one leading to the new child:
						//
						//      ...
						//     /
						//  kin - ...
						//     \
						//      pump (child)
						//
						child := node{suf: prefixOfHost}
						child.add(p.Scheme, p.Port, arbitrarySubs)
						n.addEdge(label2, &child)
						break
					}
					// Such an edge was found. Follow it and keep searching.
					host = prefixOfHost
					n, _ = last(n.children)
					continue
				}
			} else {
				// If !ok2, host is a strict suffix of n.suf.
				// Example:
				//  - n.suf: akin
				//  - host:   kin
				//
				// However, because of how we sort ps before inserting
				// them into t, this case cannot occur.
				//
				// If ok2, neither n.suf nor host is a suffix (strict or not)
				// of the other. Moreover, because of how we sort ps before
				// inserting them into t, we know that label1 < label2.
				// Example:
				//  - n.suf:    akin
				//  - host:  pumpkin
				//
				// Perform a two-way split of n:
				//
				//   kin - a (child1)
				//      \
				//       pump (child2)
				//
				child1 := *n
				child1.suf = prefixOfNSuf
				child2 := node{suf: prefixOfHost}
				child2.add(p.Scheme, p.Port, arbitrarySubs)
				*n = node{suf: suf}
				n.addEdge(label1, &child1)
				n.addEdge(label2, &child2)
				break
			}
		}
	}
	return t
}

// IsEmpty reports whether t is empty.
func (t *Tree) IsEmpty() bool {
	return t.root == nil
}

// Contains reports whether t contains o.
func (t *Tree) Contains(o *Origin) bool {
	if t.IsEmpty() {
		return false
	}
	host := o.Host
	n := t.root
	for {
		prefixOfHost, _, suf := splitAtCommonSuffix(host, n.suf)
		if len(suf) != len(n.suf) {
			// n.suf is NOT a suffix of host. Example:
			// - n.suf: akin
			// - host:   kin
			return false
		}
		// n.suf is a suffix of host.

		label, ok := last([]byte(prefixOfHost))
		if !ok {
			// n.suf == host
			return n.contains(o.Scheme, o.Port, false)
		}

		// host is a strict suffix of n.suf.
		// Example:
		// - n.suf: .kin
		// - host: a.kin

		// Check whether n contains port for arbitrary subdomains.
		if n.contains(o.Scheme, o.Port, true) {
			return true
		}

		// Look for an edge labeled label stemming from n.
		i, found := slices.BinarySearch(n.edges, label)
		if !found {
			return false
		}
		// Such an edge was found. Follow it and keep searching.
		host = prefixOfHost
		n = n.children[i]
	}
}

// last, if s is not empty, returns the last element in s and true;
// otherwise, it returns the zero value and false.
func last[S []T, T any](s S) (T, bool) {
	if len(s) == 0 {
		var zero T
		return zero, false
	}
	return s[len(s)-1], true
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
		if t.IsEmpty() {
			return
		}
		t.root.elems("", yield)
	}
}

// A node represents a node of a Tree.
// Invariants:
//   - len(edges) == len(children)
//   - len(schemes) == len(ports)
type node struct {
	// suf is the suffix of this node (ASCII only).
	suf string
	// edges are the edges to the children of this node.
	edges []byte
	// children are the children of this node ("parallels" edges slice).
	children []*node
	// schemes are the schemes of this node.
	schemes []string
	// ports are the ports associated to this node's schemes ("parallels"
	// schemes slice).
	ports [][]int
}

// add adds the pair (scheme, port) in n, possibly with arbitrary subdomains.
func (n *node) add(scheme string, port int, arbitrarySubs bool) {
	arbitraryPort := arbitraryPort // shadows package-level constant
	if arbitrarySubs {
		port, arbitraryPort = offset(port, arbitraryPort)
	}
	// Because of how we sort patterns before inserting them into the tree,
	// if scheme appears in n.schemes, it has to be at the end.
	if lastScheme, ok := last(n.schemes); !ok || lastScheme != scheme {
		n.schemes = append(n.schemes, scheme)
		n.ports = append(n.ports, []int{port})
		return
	}
	ports, _ := last(n.ports) // Since n.schemes is non-empty, so is n.ports.
	if _, found := slices.BinarySearch(ports, arbitraryPort); found {
		// Adding (scheme, port) in n would cause redundancy. Let's not.
		return
	}
	// Because of how we sort and compact patterns before inserting them into
	// the tree, we know that ports[len(ports)-1] < port.
	ports = append(ports, port)
	n.ports[len(n.ports)-1] = ports
}

// offset returns the results of subtracting portOffset from both port and
// arbitraryPort.
func offset(port, arbitraryPort int) (int, int) {
	return port - portOffset, arbitraryPort - portOffset
}

// An offset used for storing ports corresponding to arbitrary subdomains.
const portOffset = math.MaxUint16 + 2

// contains reports whether n contains the pair (scheme, port), possibly with
// arbitrary subdomains.
func (n *node) contains(scheme string, port int, arbitrarySubs bool) (found bool) {
	arbitraryPort := arbitraryPort // shadows package-level constant
	if arbitrarySubs {
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

// addEdge adds an edge labeled label and leading to child in n.
// Preconditions:
//   - n.edges is sorted in increasing order
//   - n.edges[len(n.edges)-1] < label
func (n *node) addEdge(label byte, child *node) {
	n.edges = append(n.edges, label)
	n.children = append(n.children, child)
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
