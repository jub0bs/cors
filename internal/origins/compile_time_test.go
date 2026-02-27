package origins

import "math"

var _ [absentPort][-absentPort]struct{} // => absentPort == 0

var _ [arbitraryPort + 1][-arbitraryPort - 1]struct{} // => arbitraryPort == -1

// Check that portOffset == math.MaxUint16 + 2. Hence, portOffset "straddles"
// (and exactly so) the entire range of valid Pattern.Port values, i.e.
// [-1, math.MaxUint16].
var _ [portOffset - math.MaxUint16 - 2][-portOffset + math.MaxUint16 + 2]struct{}
