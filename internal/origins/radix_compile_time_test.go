package origins

import "math"

var ( // compile-time checks
	_ [wildcardPort - 1 - math.MaxUint16]struct{} // wildcardPort > math.MaxUint16
	_ [math.MaxInt - wildcardPort]struct{}        // wildcardPort <= math.MaxInt
	_ [portOffset - 1 - wildcardPort]struct{}     // portOffset > wildcardPort
	_ [-(math.MinInt + portOffset)]struct{}       // -portOffset >= math.MinInt
)
