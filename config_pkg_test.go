package cors

import (
	"strings"
	"testing"

	"github.com/jub0bs/cors/internal/sortedset"
)

func Test_joinWithCommas_panic(t *testing.T) {
	const maxInt = 1024
	var set sortedset.Set
	set.Add(strings.Repeat("a", maxInt+1))
	defer func() {
		if recover() == nil {
			t.Error("got no panic; want panic")
		}
	}()
	joinWithCommas(set, maxInt)
}
