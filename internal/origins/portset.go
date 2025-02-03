package origins

// A PortSet represents a set of ports.
// The zero value of PortSet is an empty set of ports.
type PortSet map[int]struct{}

// Add adds port to ps.
func (ps *PortSet) Add(port int) {
	if ps.Contains(wildcardPort) { // nothing to do
		return
	}
	if port == wildcardPort {
		// Use structural sharing to avoid unnecessary allocations.
		*ps = wildcardPortSingleton
		return
	}
	if *ps == nil {
		*ps = make(PortSet)
	}
	(*ps)[port] = struct{}{}
}

// Contains returns true if port is an element of ps, and false otherwise.
func (ps PortSet) Contains(port int) (found bool) {
	_, found = ps[port]
	if !found {
		_, found = ps[wildcardPort]
	}
	return found
}

// wildcardPort is a sentinel value that subsumes all others.
const wildcardPort = -1

var wildcardPortSingleton = PortSet{wildcardPort: {}}
