package origins

import "math"

var _ [absentPort][-absentPort]struct{} // => absentPort == 0

var _ [arbitraryPort + 1][-arbitraryPort - 1]struct{} // => arbitraryPort == -1

// Check that portOffset straddles the entire range of Pattern.Port values.
var _ [portOffset - math.MaxUint16 - 2]struct{} // portOffset >= math.MaxUint16 + 2
