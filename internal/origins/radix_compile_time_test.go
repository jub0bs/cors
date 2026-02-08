package origins

import "math"

var _ [wildcardPort + 1][-wildcardPort - 1]struct{} // => wildcardPort == -1

// Check that portOffset straddles the entire range of Pattern.Port values.
var _ [portOffset - math.MaxUint16 - 2]struct{} // portOffset >= math.MaxUint16 + 2
