package origins

import (
	"cmp"
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
// Invariant:
//   - len(schemes) == len(ports)
type node struct {
	// suf of this node (not restricted to ASCII or even valid UTF-8)
	suf string
	// edges to children of this node
	edges edges
	// schemes of this node
	schemes []string
	// ports associated to schemes ("parallels" schemes slice)
	ports [][]int
}

type edges = map[byte]*node

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
	i := slices.Index(n.schemes, scheme)
	if i < 0 {
		n.schemes = append(n.schemes, scheme)
		n.ports = append(n.ports, []int{port})
		return
	}
	ports := n.ports[i]

	if port == wildcardPort {
		hasSameSignAsPort := func(p int) bool {
			return cmp.Less(p, 0) == cmp.Less(port, 0)
		}
		ports = slices.DeleteFunc(ports, hasSameSignAsPort)
	}
	ports = append(ports, port)
	n.ports[i] = ports
}

func (n *node) contains(scheme string, port int, wildcardSubs bool) (found bool) {
	wildcardPort := wildcardPort // shadows package-level constant
	if wildcardSubs {
		port -= portOffset
		wildcardPort -= portOffset
	}
	i := slices.Index(n.schemes, scheme) // we expect low cardinality, a linear scan should do
	if i < 0 {
		return
	}
	for _, p := range n.ports[i] {
		if p == port || p == wildcardPort {
			return true
		}
	}
	return false
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
	for i := range n.schemes {
		prefix := n.schemes[i] + schemeHostSep
		for _, port := range n.ports[i] {
			prefix := prefix // deliberate shadowing
			if port < 0 {
				prefix += subdomainWildcard
				port += portOffset
			}
			s := prefix + suf
			switch port {
			case 0: // deliberately empty case
			case wildcardPort:
				s += ":" + portWildcard
			default:
				s += ":" + strconv.Itoa(port)
			}
			*dst = append(*dst, s)
		}
	}
	for _, child := range n.edges {
		child.elems(dst, suf)
	}
}
