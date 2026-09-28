package cors

import (
	"testing"

	"github.com/jub0bs/cors/internal/sortedset"
)

func Test_joinWithCommas_panic(t *testing.T) {
	const maxInt = 6
	var set sortedset.Set
	for _, str := range []string{"a", "b", "c", "d"} {
		set.Add(str)
	}
	defer func() {
		if recover() == nil {
			t.Error("got no panic; want panic")
		}
	}()
	joinWithCommas(set, maxInt) // 7 > maxInt
}
