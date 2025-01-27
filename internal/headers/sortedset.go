package headers

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

// Add adds e to set without enforcing set's invariants;
// see method [SortedSet.Fix].
func (set *SortedSet) Add(e string) {
	if set.m == nil {
		set.m = make(map[string]int)
	}
	set.m[e] = 0 // dummy value
}

// Fix restores set's invariants.
func (set *SortedSet) Fix() {
	elems := make([]string, 0, len(set.m))
	for e := range set.m {
		elems = append(elems, e)
	}
	slices.Sort(elems)
	for i, s := range elems {
		set.maxLen = max(set.maxLen, len(s))
		set.m[s] = i
	}
}

// Size returns the cardinality of set.
func (set SortedSet) Size() int {
	return len(set.m)
}

// Accepts reports whether values is a sequence of [list-based field values]
// whose elements are
//   - all members of set,
//   - sorted in lexicographical order,
//   - unique.
//
// Accepts requires a preliminary call to method [SortedSet.Fix].
//
// This methods's parameter is a slice of strings rather than just a string
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
// Therefore, this method only tolerates a small number (1) of OWS bytes
// before and/or after each element. This divergence from RFC 9110 is expected
// to strike a good balance between interoperability and performance.
//
// Moreover, this method tolerates a small number (16) of empty list elements,
// in accordance with [RFC 9110]'s recommendation (section 5.6.1.2).
//
// [RFC 9110]: https://httpwg.org/specs/rfc9110.html
// [list-based field values]: https://httpwg.org/specs/rfc9110.html#abnf.extension
// [some reportedly do]: https://github.com/rs/cors/issues/184
// [the Fetch standard]: https://fetch.spec.whatwg.org
func (set SortedSet) Accepts(values []string) bool {
	// effectively constant
	maxLen := MaxOWSBytes + set.maxLen + MaxOWSBytes + 1 // +1 for comma

	var (
		posOfLastNameSeen = -1
		name              string
		commaFound        bool
		emptyElements     int
		ok                bool
	)
	for _, str := range values {
		for {
			// As a defense against maliciously long names in str, we process
			// only a small number of str's leading bytes per iteration.
			name, str, commaFound = cutAtComma(str, maxLen)
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
				if !commaFound { // We have now exhausted the names in str.
					break
				}
				continue
			}
			pos, ok := set.m[name]
			if !ok {
				return false
			}
			// The names in str are expected to be sorted in lexicographical order
			// and to each appear at most once.
			// Therefore, the positions (in set) of the names that
			// appear in str should form a strictly increasing sequence.
			// If that's not actually the case, bail out.
			if pos <= posOfLastNameSeen {
				return false
			}
			posOfLastNameSeen = pos
			if !commaFound { // We have now exhausted the names in str.
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
func cutAtComma(str string, n int) (before, after string, found bool) {
	// Note: this implementation draws inspiration from strings.Cut's.
	end := min(len(str), n)
	if i := strings.IndexByte(str[:end], ','); i >= 0 {
		after = str[i+1:] // deal with this first to save one bounds check
		return str[:i], after, true
	}
	return str, "", false
}

// ToSortedSlice returns a slice containing set's elements sorted in
// lexicographical order.
//
// ToSortedSlice requires a preliminary call to method [SortedSet.Fix].
func (set SortedSet) ToSortedSlice() []string {
	elems := make([]string, len(set.m))
	for elem, i := range set.m {
		elems[i] = elem // safe indexing, by construction of SortedSet
	}
	return elems
}
