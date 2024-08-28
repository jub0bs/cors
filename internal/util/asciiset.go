package util

// An ASCIISet represents a set of ASCII bytes.
type ASCIISet [8]uint32

// MakeASCIISet creates a set of ASCII characters and reports whether all
// characters in chars are ASCII.
// All bytes in chars are assumed to be less < utf8.RuneSelf.
// This implementation is adapted from that of the strings package.
func MakeASCIISet(chars string) ASCIISet {
	var as ASCIISet
	for i := 0; i < len(chars); i++ {
		c := chars[i]
		as[c/32] |= 1 << (c % 32)
	}
	return as
}

// Contains reports whether c is inside the set.
func (as *ASCIISet) Contains(c byte) bool {
	return (as[c/32] & (1 << (c % 32))) != 0
}
