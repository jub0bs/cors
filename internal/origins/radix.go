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
			label1, ok1 := last(prefixOfNSuf)
			label2, ok2 := last(prefixOfHost)
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
						child = &node{suf: prefixOfHost}
						child.add(p.Scheme, p.Port, arbitrarySubs)
						n.addEdge(label2, child)
						break
					}
					// Such an edge was found. Follow it and keep searching.
					host = prefixOfHost
					n = child
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

// splitAtCommonSuffix finds the longest suffix common to x and y and returns
// x and y both trimmed of that suffix along with the suffix itself.
func splitAtCommonSuffix(x, y string) (string, string, string) {
	s, l := x, y // s for short, l for long
	if len(l) < len(s) {
		s, l = l, s
	}
	i := len(s)
	l = l[len(l)-i:]
	_ = l[:i] // hoist bounds checks on l out of the loop
	for ; 0 < i && s[i-1] == l[i-1]; i-- {
		// deliberately empty body
	}
	return x[:len(x)-len(s)+i], y[:len(y)-len(s)+i], s[i:]
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
	host := o.Host
	n := t.root
	for {
		prefixOfHost, suf := trimCommonSuffix(host, n.suf)
		if len(suf) != len(n.suf) {
			// n.suf is NOT a suffix of host. Example:
			// - n.suf: akin
			// - host:   kin
			return false
		}
		// n.suf is a suffix of host.

		label, ok := last(prefixOfHost)
		if !ok {
			// n.suf == host
			return n.contains(o.Scheme, o.Port, false)
		}

		// host is a strict suffix of n.suf.
		// Example:
		// - n.suf: kin
		// - host: akin

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
		host = prefixOfHost
		n = child
	}
}

// trimCommonSuffix finds the longest suffix common to x and y and returns
// x trimmed of that suffix along with the suffix itself.
//
// Note: trimCommonSuffix is a stripped-down version of splitAtCommonSuffix
// that is both inlinable and free of bounds checks.
func trimCommonSuffix(x, y string) (string, string) {
	i, j := len(x), len(y)
	// Note: an extra j < len(y) check is currently necessary to hoist the
	// bounds checks for y[j] out of the loop below; see go.dev/issue/45078.
	for 0 < i && 0 < j && j <= len(y) {
		if x[i-1] != y[j-1] {
			return x[:i], x[i:]
		}
		i--
		j--
	}
	if len(y) > len(x) {
		return "", y[len(y)-len(x):]
	}
	return x[:len(x)-len(y)], x[len(x)-len(y):]
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
	suf      string
	children mapping[byte, *node]
	leaves   mapping[string, mapping[int, struct{}]]
}

// add adds the pair (scheme, port) in n, possibly with arbitrary subdomains.
func (n *node) add(scheme string, port int, arbitrarySubs bool) {
	arbitraryPort := arbitraryPort // shadows package-level constant
	if arbitrarySubs {
		port, arbitraryPort = offset(port, arbitraryPort)
	}
	// Because of how we sort patterns before inserting them into the tree,
	// if scheme appears in n.schemes, it has to be at the end.
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

// addEdge adds an edge labeled label and leading to child in n.
// Preconditions:
//   - n.edges is sorted in increasing order
//   - n.edges[len(n.edges)-1] < label
func (n *node) addEdge(label byte, child *node) {
	n.children.upsert(label, child)
}

// elems reports whether f(x) is true for the textual representation
// (using suf as base suffix) of every element x in n.
func (n *node) elems(suf string, f func(string) bool) bool {
	suf = n.suf + suf
	for scheme, ports := range n.leaves.all() {
		for port := range ports.all() {
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
	for _, child := range n.children.all() {
		if !child.elems(suf, f) {
			return false
		}
	}
	return true
}
