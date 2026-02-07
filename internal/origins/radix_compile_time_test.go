package origins

import "math"

var (
	// Check (at compile time) that wildcardPort == -1.
	_ [wildcardPort + 1]struct{}  // wildcardPort >= -1
	_ [-wildcardPort - 1]struct{} // wildcardPort <= -1
)

// Check (at compile time) that portOffset straddles the entire range of
// possible values for Pattern.Port.
var _ [portOffset - math.MaxUint16 - 2]struct{} // portOffset >= math.MaxUint16 + 2
