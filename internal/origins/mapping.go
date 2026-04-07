package origins

import "iter"

// A mapping is an unordered collection of key-value pairs where the keys are
// unique. A zero mapping is empty and ready to use. A mapping tries to pick a
// representation that makes mapping.find most efficient.
// This type draws heavy inspiration from
// https://cs.opensource.google/go/go/+/refs/tags/go1.26.1:src/net/http/mapping.go.
type mapping[K comparable, V any] struct {
	few  []entry[K, V] // for few pairs
	many map[K]V       // for many pairs
}

type entry[K comparable, V any] struct {
	k K
	v V
}

const maxSlice = 8

// upsert inserts or updates a key-value pair in m.
func (m *mapping[K, V]) upsert(k K, v V) {
	switch {
	case m.many != nil: // many pairs
		m.many[k] = v
	case m.few == nil: // empty mapping
		m.few = []entry[K, V]{{k, v}}
	case len(m.few) >= maxSlice: // switch from few to many
		many := map[K]V{}
		for _, e := range m.few {
			many[e.k] = e.v
		}
		many[k] = v
		m.many = many
		m.few = nil
	default: // few (< maxSlice) pairs
		few := m.few // eliminate bounds checks below
		for i, e := range few {
			if e.k == k {
				few[i].v = v
				return
			}
		}
		m.few = append(few, entry[K, V]{k, v})
	}
}

// find returns the value corresponding to the given key and true if the key is
// present in m; otherwise, it returns the zero value and false.
func (m *mapping[K, V]) find(target K) (v V, found bool) {
	if m.many != nil { // many pairs
		v, found = m.many[target]
		return
	}
	// few (<= maxSlice) pairs
	// m.few is not sorted in any way, but linear search is fast enough,
	// given m.few's modest length.
	for _, e := range m.few {
		if e.k == target {
			return e.v, true
		}
	}
	return
}

// all returns an iterator over the key-value pairs in m.
func (m *mapping[K, V]) all() iter.Seq2[K, V] {
	return func(yield func(k K, v V) bool) {
		if m.many != nil { // many pairs
			for k, v := range m.many {
				if !yield(k, v) {
					return
				}
			}
		}
		// few (<= maxSlice) pairs
		for _, e := range m.few {
			if !yield(e.k, e.v) {
				return
			}
		}
	}
}
