package util

import (
	"slices"
	"strings"
)

// A SortedSet represents a mathematical set of strings sorted in
// lexicographical order.
// Each element has a unique position ranging from 0 (inclusive)
// to the set's cardinality (exclusive).
// The zero value represents an empty set.
type SortedSet struct {
	m      map[string]int
	maxLen int
}

// NewSortedSet returns a SortedSet that contains all of elems,
// but no other elements.
func NewSortedSet(elems ...string) SortedSet {
	slices.Sort(elems)
	elems = slices.Compact(elems)
	m := make(map[string]int)
	var maxLen int
	for i, s := range elems {
		maxLen = max(maxLen, len(s))
		m[s] = i
	}
	res := SortedSet{
		m:      m,
		maxLen: maxLen,
	}
	return res
}

// Size returns the cardinality of set.
func (set SortedSet) Size() int {
	return len(set.m)
}

// String sorts joins the elements of set (in lexicographical order)
// with a comma and returns the resulting string.
func (set SortedSet) String() string {
	elems := make([]string, len(set.m))
	for elem, i := range set.m {
		elems[i] = elem // safe indexing, by construction of SortedSet
	}
	return strings.Join(elems, ",")
}

// Subsumes reports whether csv is a sequence of comma-separated names that are
//   - all elements of set,
//   - sorted in lexicographically order,
//   - unique.
func (set SortedSet) Subsumes(csv string) bool {
	if csv == "" {
		return true
	}
	posOfLastNameSeen := -1
	chunkSize := set.maxLen + 1 // (to accommodate for at least one comma)
	for {
		// As a defense against maliciously long names in csv,
		// we only process at most chunkSize bytes per iteration.
		end := min(len(csv), chunkSize)
		comma := strings.IndexByte(csv[:end], ',')
		var name string
		if comma == -1 {
			name = csv
		} else {
			name = csv[:comma]
		}
		pos, found := set.m[name]
		if !found {
			return false
		}
		// The names in csv are expected to be sorted in lexicographical order
		// and appear at most once in csv.
		// Therefore, the positions (in set) of the names that
		// appear in csv should form a strictly increasing sequence.
		// If that's not actually the case, bail out.
		if pos <= posOfLastNameSeen {
			return false
		}
		posOfLastNameSeen = pos
		if comma < 0 { // We've now processed all the names in csv.
			break
		}
		csv = csv[comma+1:]
	}
	return true
}
