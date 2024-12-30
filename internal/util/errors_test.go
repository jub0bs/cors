package util_test

import (
	"testing"

	"github.com/jub0bs/cors/internal/util"
)

func TestSetPkgName(t *testing.T) {
	const (
		text       = "whatever"
		newPkgName = "foo"
	)
	cases := []struct {
		desc string
		err  error
		want string
	}{
		{
			desc: "NewError",
			err:  util.NewError(text),
			want: newPkgName + ": whatever",
		}, {
			desc: "Errorf",
			err:  util.Errorf("whatever %d", 42),
			want: newPkgName + ": whatever 42",
		},
	}
	for _, tc := range cases {
		f := func(t *testing.T) {
			err, ok := tc.err.(interface{ SetPkgName(string) })
			if !ok {
				const tmpl = "no SetPkgName(string) method on the dynamic type of %s"
				t.Errorf(tmpl, tc.desc)
				return
			}
			err.SetPkgName(newPkgName)
			got := tc.err.Error()
			if got != tc.want {
				const tmpl = "got %q; want %q"
				t.Errorf(tmpl, got, tc.want)
			}
		}
		t.Run(tc.desc, f)
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
