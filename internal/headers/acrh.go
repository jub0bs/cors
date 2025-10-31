package headers

import "github.com/jub0bs/cors/internal/util"

// Check reports whether acrhs is a sequence of [list-based field values]
// whose elements are
//   - all members of set,
//   - sorted in lexicographical order,
//   - unique.
//
// This function's parameter is a slice of strings rather than just a string
// because, although [the Fetch standard] requires browsers to include at most
// one ACRH header line in CORS-preflight requests, some intermediaries may
// well (and [some reportedly do]) split that ACRH header line into multiple
// ones. Note that, because [RFC 9110] ([section 5.3]) forbids intermediaries
// from changing the order of field lines of the same name, we can expect the
// sequence of tokens in the ACRH field value to still be sorted in
// lexicographical order.
//
// Although [the Fetch standard] requires browsers to omit any whitespace
// in the value of the ACRH field, some intermediaries may well alter this
// list-based field value by sprinkling optional whitespace (OWS) around
// the value's elements.
// [RFC 9110] ([section 5.6.1.2]) requires recipients to tolerate arbitrary
// long OWS around elements of a list-based field value,
// but adherence to this requirement leads to non-negligible performance
// degradation in CORS middleware when they handle adversarial (spoofed)
// CORS-preflight requests.
// Therefore, this function only tolerates a small total (2) of OWS bytes
// before and after each element. We expect this deviation from [RFC 9110] to
// strike a good balance between interoperability and performance.
// This function also tolerates a small number (16) of empty list elements,
// in accordance with [RFC 9110] ([section 5.6.1.2]).
//
// [RFC 9110]: https://httpwg.org/specs/rfc9110.html#abnf.extension.recipient
// [list-based field values]: https://httpwg.org/specs/rfc9110.html#abnf.extension
// [section 5.3]: https://httpwg.org/specs/rfc9110.html#rfc.section.5.3
// [section 5.6.1.2]: https://httpwg.org/specs/rfc9110.html#rfc.section.5.6.1.2
// [some reportedly do]: https://github.com/rs/cors/issues/184
// [the Fetch standard]: https://fetch.spec.whatwg.org
func Check(set util.SortedSet, acrhs []string) bool {
	var (
		// position in set of the last name encountered in the ACRH field value
		pos = -1
		// total number of empty ACRH header line value and empty list elements
		emptyElements uint
	)
	for _, acrh := range acrhs {
		if acrh == "" { // empty ACRH header line value
			if emptyElements >= MaxEmptyElements {
				return false
			}
			emptyElements++
			continue
		}
		// acrh is not empty
		for looping := true; looping; {
			var (
				name      string
				owsBudget uint = MaxOWSBytes
			)
			acrh, owsBudget = consumeOWS(acrh, owsBudget)
			name, acrh = scanName(acrh, set.MaxLen())
			acrh, _ = consumeOWS(acrh, owsBudget)
			// Before processing name, let's perform some sanity checks.
			switch {
			case len(acrh) == 0:
				// name is the last element in this list-based field value;
				// stop the inner loop after the current iteration.
				looping = false
			case acrh[0] != ',':
				// If acrh isn't empty and doesn't start by a comma,
				// this header line value either contains more OWS than we
				// tolerate or it is not well-formed. Fail.
				return false
			default: // A comma was found at the start of acrh; consume it.
				acrh = acrh[1:]
			}
			// Now let's process name.
			if name == "" { // empty list element
				if emptyElements >= MaxEmptyElements {
					return false
				}
				emptyElements++
				continue
			}
			// The names in the ACRH header value are expected to be sorted in
			// lexicographical order and to each appear at most once.
			// Therefore, the positions (in set) of the names that successively
			// appear in the ACRH header value should form a strictly
			// increasing sequence. If that's not actually the case, fail.
			pos = set.IndexAfter(pos, name)
			if pos < 0 {
				return false
			}
		}
	}
	return true
}

const (
	MaxOWSBytes      = 2  // tolerated total of leading & trailing OWS bytes per element
	MaxEmptyElements = 16 // tolerated total of empty elements
)

func consumeOWS(s string, budget uint) (string, uint) {
	for len(s) > 0 && isOWS(s[0]) && budget > 0 {
		s = s[1:]
		budget--
	}
	return s, budget
}

// Note: name is not guaranteed to be a valid token.
func scanName(s string, maxLen uint) (name, rest string) {
	for i := range uint(len(s)) {
		// As a defense against maliciously long names,
		// we scan at most maxLen bytes.
		if isOWS(s[i]) || s[i] == ',' || i > maxLen {
			return s[:i], s[i:]
		}
	}
	return s, ""
}

// see https://httpwg.org/specs/rfc9110.html#whitespace
func isOWS(b byte) bool {
	return b == '\t' || b == ' '
}
