package headers

import "github.com/jub0bs/cors/internal/util"

// Check reports whether acrhs is a sequence of [list-based field values]
// whose elements are
//   - all members of set,
//   - sorted in lexicographical order,
//   - unique.
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
func Check(set util.SortedSet, acrhs []string) bool {
	// effectively constant
	maxLen := MaxOWSBytes + set.MaxLen() + MaxOWSBytes + 1 // +1 for comma
	var (
		posOfLastNameSeen = -1
		name              string
		commaFound        bool
		emptyElements     int
		ok                bool
	)
	for _, acrh := range acrhs {
		for {
			// As a defense against maliciously long names in acrh, we process
			// only a small number of acrh's leading bytes per iteration.
			name, acrh, commaFound = cutAtComma(acrh, uint(maxLen))
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
				if !commaFound { // We have now exhausted the names in acrh.
					break
				}
				continue
			}
			// The names in acrh are expected to be sorted in lexicographical order
			// and to each appear at most once.
			// Therefore, the positions (in set) of the names that
			// appear in acrh should form a strictly increasing sequence.
			// If that's not actually the case, bail out.
			i := set.IndexAfter(posOfLastNameSeen, name)
			if i < 0 {
				return false
			}
			posOfLastNameSeen = i
			if !commaFound { // We have now exhausted the names in acrh.
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

// cutAtComma slices str around the first comma that appears among (up to) the
// first n bytes of str, returning the parts of str before and after the comma.
// The found result reports whether a comma appears in that portion of str.
// If no comma appears in that portion of str, cutAtComma returns str, "", false.
func cutAtComma(str string, n uint) (before, after string, found bool) {
	for i := range min(uint(len(str)), n) {
		if str[i] == ',' {
			return str[:i], str[i+1:], true
		}
	}
	return str, "", false
}
