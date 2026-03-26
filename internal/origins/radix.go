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
		s, arbitrarySubs := strings.CutPrefix(p.HostPattern, subdomainWildcard)
		t.root = &node{suf: s}
		t.root.add(p.Scheme, p.Port, arbitrarySubs)
		// Now deal with the remaining patterns.
		ps = ps[1:]
	}
	for _, p := range ps {
		s, arbitrarySubs := strings.CutPrefix(p.HostPattern, subdomainWildcard)
		n := t.root
		for {
			prefixOfNSuf, prefixOfS, suf := splitAtCommonSuffix(n.suf, s)
			label1, ok1 := last(prefixOfNSuf)
			label2, ok2 := last(prefixOfS)
			if !ok1 {
				if !ok2 {
					// n.suf and s are equal.
					n.add(p.Scheme, p.Port, arbitrarySubs)
					break
				} else {
					// n.suf is a strict suffix of s.
					// Example:
					//  - n.suf:     kin
					//  - s:     pumpkin
					if n.contains(p.Scheme, p.Port, true) {
						// Inserting p in t would cause redundancy. Let's not.
						break
					}
					// Look for an edge labeled label2 stemming from n.
					child, ok := n.children.find(label2)
					if !ok {
						// No such edge was found.
						// Create one leading to the new child:
						//
						//      ...
						//     /
						//  kin - ...
						//     \
						//      pump (child)
						//
						child = &node{suf: prefixOfS}
						child.add(p.Scheme, p.Port, arbitrarySubs)
						n.children.upsert(label2, child)
						break
					}
					// Such an edge was found. Follow it and keep searching.
					s = prefixOfS
					n = child
					continue
				}
			} else {
				// If !ok2, s is a strict suffix of n.suf.
				// Example:
				//  - n.suf: akin
				//  - s:      kin
				//
				// However, because of how we sort ps before inserting
				// them into t, this case cannot occur.
				//
				// If ok2, neither n.suf nor s is a suffix (strict or not)
				// of the other.
				// Example:
				//  - n.suf:    akin
				//  - s:     pumpkin
				//
				// Perform a two-way split of n:
				//
				//   kin - a (child1)
				//      \
				//       pump (child2)
				//
				child1 := &node{
					suf:      prefixOfNSuf,
					children: n.children,
					leaves:   n.leaves,
				}
				child2 := &node{suf: prefixOfS}
				child2.add(p.Scheme, p.Port, arbitrarySubs)
				*n = node{suf: suf}
				n.children.upsert(label1, child1)
				n.children.upsert(label2, child2)
				break
			}
		}
	}
	return t
}

// last, if s is not empty, returns the last byte in s and true;
// otherwise, it returns zero and false.
func last(s string) (byte, bool) {
	if len(s) == 0 {
		return 0, false
	}
	return s[len(s)-1], true
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
	s := o.Host
	n := t.root
	for {
		prefixOfS, ok := strings.CutSuffix(s, n.suf)
		if !ok {
			// n.suf is NOT a suffix of s. Example:
			// - n.suf: akin
			// - s:      kin
			return false
		}
		// n.suf is a suffix of s.

		label, ok := last(prefixOfS)
		if !ok {
			// n.suf == s
			return n.contains(o.Scheme, o.Port, false)
		}

		// n.suf is a strict suffix of s.
		// Example:
		// - n.suf: kin
		// - s:    akin

		// Check whether n contains port for arbitrary subdomains.
		if n.contains(o.Scheme, o.Port, true) {
			return true
		}

		// Look for an edge labeled label stemming from n.
		child, found := n.children.find(label)
		if !found {
			return false
		}
		// Such an edge was found. Follow it and keep searching.
		s = prefixOfS
		n = child
	}
}

// Elems returns an iterator over textual representations of t's elements.
// The order is unspecified and unstable, in the sense that different calls to
// t.Elems may yield the elements in a different order.
func (t *Tree) Elems() iter.Seq[string] {
	return func(yield func(string) bool) {
		if t.IsEmpty() {
			return
		}
		t.root.elems("", yield)
	}
}

// A node represents a node of a Tree.
type node struct {
	// suf is the suffix of this node.
	suf string
	// children represents edges to children of this node.
	children mapping[byte, *node]
	// leaves represents scheme-ports pairs in this node.
	leaves mapping[string, mapping[int, struct{}]]
}

// add adds the pair (scheme, port) in n, possibly with arbitrary subdomains.
func (n *node) add(scheme string, port int, arbitrarySubs bool) {
	port, arbitraryPort := offset(port, arbitraryPort, arbitrarySubs)
	// arbitraryPort shadows the homonymous package-level constant.
	ports, ok := n.leaves.find(scheme)
	if !ok {
		ports.upsert(port, struct{}{})
		n.leaves.upsert(scheme, ports)
	}
	if _, found := ports.find(arbitraryPort); found {
		// Adding (scheme, port) in n would cause redundancy. Let's not.
		return
	}
	ports.upsert(port, struct{}{})
	n.leaves.upsert(scheme, ports)
}

// contains reports whether n contains the pair (scheme, port), possibly with
// arbitrary subdomains.
func (n *node) contains(scheme string, port int, arbitrarySubs bool) (found bool) {
	port, arbitraryPort := offset(port, arbitraryPort, arbitrarySubs)
	// arbitraryPort shadows the homonymous package-level constant.
	ports, found := n.leaves.find(scheme)
	if !found {
		return
	}
	_, found = ports.find(port)
	if found {
		return
	}
	_, found = ports.find(arbitraryPort)
	return
}

// elems reports whether f(x) is true for the textual representation
// (using suf as base suffix) of every element x in n.
func (n *node) elems(suf string, f func(string) bool) bool {
	suf = n.suf + suf
	for scheme, ports := range n.leaves.all() {
		for port := range ports.all() {
			port, maybeWildcard := undoOffset(port)
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
	for _, child := range n.children.all() {
		if !child.elems(suf, f) {
			return false
		}
	}
	return true
}

// offset returns the results of subtracting portOffset from both port and
// arbitraryPort.
func offset(port, arbitraryPort int, arbitrarySubs bool) (int, int) {
	if !arbitrarySubs {
		return port, arbitraryPort
	}
	return port - portOffset, arbitraryPort - portOffset
}

// An offset used for storing ports corresponding to arbitrary subdomains.
const portOffset = math.MaxUint16 + 2

// undoOffset essentially undoes what offset does.
func undoOffset(maybeOffsetPort int) (port int, maybeWildcard string) {
	if maybeOffsetPort < arbitraryPort {
		return maybeOffsetPort + portOffset, subdomainWildcard
	}
	return maybeOffsetPort, ""
}
