package headers

import (
	"net/http"
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
//   - sorted in lexicographical order,
//   - unique.
func (set SortedSet) Subsumes(csv string) bool {
	if csv == "" {
		return true
	}
	var (
		posOfLastNameSeen = -1
		name              string
		commaFound        bool
	)
	for {
		// As a defense against maliciously long names in csv,
		// we process only a small number of csv's leading bytes per iteration.
		name, csv, commaFound = cutAtComma(csv, set.maxLen+1) // +1 for comma
		pos, ok := set.m[name]
		if !ok {
			return false
		}
		// The names in csv are expected to be sorted in lexicographical order
		// and to each appear at most once.
		// Therefore, the positions (in set) of the names that
		// appear in csv should form a strictly increasing sequence.
		// If that's not actually the case, bail out.
		if pos <= posOfLastNameSeen {
			return false
		}
		posOfLastNameSeen = pos
		if !commaFound { // We have now exhausted the names in csv.
			return true
		}
	}
}

// cutAtComma slices s around the first comma that appears among (up to) the
// first n bytes of s, returning the parts of s before and after the comma.
// The found result reports whether a comma appears in that portion of s.
// If no comma appears in that portion of s, cutAtComma returns s, "", false.
func cutAtComma(s string, n int) (before, after string, found bool) {
	// Note: this implementation draws inspiration from strings.Cut's.
	end := min(len(s), n)
	if i := strings.IndexByte(s[:end], ','); i >= 0 {
		after = s[i+1:] // deal with this first to save one bounds check
		return s[:i], after, true
	}
	return s, "", false
}

// ToSortedSlice applies http.CanonicalHeaderKey to each element of s
// and returns a sorted slice containing the results.
func (set SortedSet) ToSortedSlice() []string {
	res := make([]string, 0, set.Size())
	for elem := range set.m {
		res = append(res, http.CanonicalHeaderKey(elem))
	}
	slices.Sort(res)
	return res
}
