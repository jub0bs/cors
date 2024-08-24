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

// String joins the elements of set (sorted in lexicographical order)
// with a comma and returns the resulting string.
func (set SortedSet) String() string {
	elems := make([]string, len(set.m))
	for elem, i := range set.m {
		elems[i] = elem // safe indexing, by construction of SortedSet
	}
	return strings.Join(elems, ",")
}

// Accepts reports whether values is a sequence of [list-based field values]
// whose elements are
//   - all members of set,
//   - sorted in lexicographical order,
//   - unique.
//
// This function's parameter is a slice of strings rather than just a string
// because, although [the Fetch standard] requires browsers to include at most
// one ACRH field line in CORS-preflight requests, some intermediaries may well
// (and [some reportedly do]) split it into multiple ACRH field lines.
// Note that, because [RFC 9110] (section 5.3) forbids intermediaries from
// changing the order of field lines of the same name, we can expect the
// overall sequence of elements to still be sorted in lexicographical order.
//
// Although [the Fetch standard] requires browsers to omit any whitespace
// in the value of the ACRH field, some intermediaries may well alter this
// list-based field's value by sprinkling optional whitespace (OWS) around
// the value's elements.
// [RFC 9110] (section 5.6.1.2) requires recipients to tolerate arbitrary long
// OWS around elements of a list-based field value,
// but adherence to this requirement leads to non-negligible performance
// degradation in CORS middleware in the face of adversarial (spoofed)
// CORS-preflight requests.
// Therefore, this function only tolerates a small number (1) of OWS bytes
// before and/or after each element. This deviation from RFC 9110 is expected
// to strike a good balance between interoperability and performance.
//
// Moreover, this function tolerates a small number (16) of empty list elements,
// in accordance with [RFC 9110]'s recommendation (section 5.6.1.2).
//
// [RFC 9110]: https://httpwg.org/specs/rfc9110.html
// [list-based field values]: https://httpwg.org/specs/rfc9110.html#abnf.extension
// [some reportedly do]: https://github.com/rs/cors/issues/184
// [the Fetch standard]: https://fetch.spec.whatwg.org
func (set SortedSet) Accepts(values []string) bool {
	var ( // effectively constant
		maxLen = MaxOWSBytes + set.maxLen + MaxOWSBytes + 1 // +1 for comma
	)
	var (
		posOfLastNameSeen = -1
		name              string
		commaFound        bool
		emptyElements     int
		ok                bool
	)
	for _, s := range values {
		for {
			// As a defense against maliciously long names in csv,
			// we process only a small number of csv's leading bytes per iteration.
			name, s, commaFound = cutAtComma(s, maxLen)
			name, ok = TrimOWS(name, MaxOWSBytes)
			if !ok {
				return false
			}
			if name == "" {
				// RFC 9110 requires recipients to tolerate
				// "a reasonable number of empty list elements"; see
				// https://httpwg.org/specs/rfc9110.html#abnf.extension.recipient.
				emptyElements++
				if emptyElements > MaxEmptyElements {
					return false
				}
				if !commaFound { // We have now exhausted the names in csv.
					break
				}
				continue
			}
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
				break
			}
		}
	}
	return true
}

const (
	MaxOWSBytes      = 1  // number of leading/trailing OWS bytes tolerated
	MaxEmptyElements = 16 // number of empty list elements tolerated
)

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
