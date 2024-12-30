package util_test

import (
	"testing"

	"github.com/jub0bs/cors/internal/util"
)

func TestNewError(t *testing.T) {
	const (
		text = "whatever"
		want = "cors: whatever"
	)
	got := util.NewError(text).Error()
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestErrorf(t *testing.T) {
	const format = "%s %s"
	args := []any{"foo", "bar"}
	const want = "cors: foo bar"
	got := util.Errorf(format, args...).Error()
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestInvalidOriginPatternErr(t *testing.T) {
	const (
		pattern = "foobar"
		want    = `cors: invalid origin pattern "foobar"`
	)
	got := util.InvalidOriginPatternErr(pattern).Error()

	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}
