package origins

import "math"

var ( // compile-time checks
	_ [absentPort][-absentPort]struct{}            // => absentPort == 0
	_ [arbitraryPort - 1 - math.MaxUint16]struct{} // arbitraryPort > math.MaxUint16
	_ [math.MaxInt - arbitraryPort]struct{}        // arbitraryPort <= math.MaxInt
	_ [portOffset - 1 - arbitraryPort]struct{}     // portOffset > arbitraryPort
	_ [-(math.MinInt + portOffset)]struct{}        // -portOffset >= math.MinInt
)
