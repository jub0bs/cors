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

// IsEmpty reports whether t is empty.
func (t *Tree) IsEmpty() bool {
	return t.root.schemes == nil && t.root.children == nil
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
		// After splitting:  child' -- grandChild1
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
// Invariants:
//   - len(edges) == len(children)
//   - len(schemes) == len(ports)
type node struct {
	// suf of this node (not restricted to ASCII or even valid UTF-8)
	suf string
	// edges to children of this node
	edges []byte
	// children of this node ("parallels" edges slice)
	children []node
	// schemes of this node
	schemes []string
	// ports associated to this node's schemes ("parallels" schemes slice)
	ports [][]int
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
	if n.contains(scheme, port, wildcardSubs) {
		return
	}
	i, found := slices.BinarySearch(n.schemes, scheme)
	if !found {
		n.schemes = insert(n.schemes, i, scheme)
		n.ports = insert(n.ports, i, []int{port})
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

func insert[T any](s []T, i int, v T) []T {
	// see https://go.dev/wiki/SliceTricks#insert
	var dummy T
	s = append(s, dummy)
	copy(s[i+1:], s[i:])
	s[i] = v
	return s
}

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
		n.edges = insert(n.edges, i, label)
		n.children = insert(n.children, i, child)
		return &n.children[i]
	}
	n.children[i] = child
	return &n.children[i]
}

// elems adds textual representations of n's elements
// (using suf as base suffix) to dst.
func (n *node) elems(dst *[]string, suf string) {
	suf = n.suf + suf
	// We iterate over n.ports rather than n.schemes in order to
	// hoist most bounds checks out of the (outer) loop.
	for i, ports := range n.ports {
		scheme := n.schemes[i]
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
			*dst = append(*dst, s)
		}
	}
	for i := range n.children {
		n.children[i].elems(dst, suf)
	}
}
