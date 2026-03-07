package origins

import "iter"

// A mapping is a collection of key-value pairs where the keys are unique.
// A zero mapping is empty and ready to use.
// A mapping tries to pick a representation that makes [mapping.find] most efficient.
type mapping[K comparable, V any] struct {
	few  *few[K, V] // for few pairs
	many map[K]V    // for many pairs
}

type few[K comparable, V any] struct { // more space-efficient than a slice of struct{K, V}
	keys   [maxSlice]K
	values [maxSlice]V
	size   uint8
}

const maxSlice = 8

// upsert inserts or updates a key-value pair in the mapping.
func (h *mapping[K, V]) upsert(k K, v V) {
	if h.many != nil { // many pairs
		h.many[k] = v
		return
	} else if f := h.few; f == nil { // empty mapping
		f = new(few[K, V])
		f.keys[0] = k
		f.values[0] = v
		f.size = 1
		h.few = f
		return
	} else if size := f.size; size > maxSlice {
		panic("unreachable")
	} else if size == maxSlice { // few to many pairs
		m := map[K]V{}
		for i := range size {
			m[f.keys[i]] = f.values[i]
		}
		m[k] = v
		h.many = m
		h.few = nil
		return
	} else { // few pairs
		for i, key := range f.keys[:size] {
			if key == k {
				f.values[i] = v
				return
			}
		}
		f.keys[size] = k
		f.values[size] = v
		f.size++
	}
}

// find returns the value corresponding to the given key.
// The second return value is false if there is no value
// with that key.
func (h *mapping[K, V]) find(target K) (v V, found bool) {
	if h.many != nil {
		v, found = h.many[target]
		return v, found
	} else if f := h.few; f == nil {
		return v, false
	} else if size := f.size; size > maxSlice {
		panic("unreachable")
	} else {
		for i := range size {
			if f.keys[i] == target {
				return f.values[i], true
			}
		}
		return
	}
}

// eachPair calls f for each pair in the mapping.
// If f returns false, pairs returns immediately.
func (h *mapping[K, V]) all() iter.Seq2[K, V] {
	return func(yield func(k K, v V) bool) {
		if h.many != nil {
			for k, v := range h.many {
				if !yield(k, v) {
					return
				}
			}
		} else if f := h.few; f == nil {
			return
		} else if size := f.size; size > maxSlice {
			panic("unreachable")
		} else {
			for i := range size {
				if !yield(f.keys[i], f.values[i]) {
					return
				}
			}
		}
	}
}
