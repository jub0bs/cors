package cfgerrors_test

import (
	"errors"
	"iter"
	"net/http"
	"strings"
	"testing"

	"github.com/jub0bs/cors/cfgerrors"
)

type TestCase struct {
	desc      string
	err       error
	want      []error
	breakWhen func(error) bool
}

var cases = []TestCase{
	{
		desc:      "nil error",
		err:       nil,
		want:      nil,
		breakWhen: alwaysFalse,
	}, {
		desc:      "single joined error, no break",
		err:       errors.Join(err1),
		want:      []error{err1},
		breakWhen: alwaysFalse,
	}, {
		desc:      "single joined error, break early",
		err:       errors.Join(err1),
		want:      nil,
		breakWhen: equal(err1),
	}, {
		desc:      "multiple joined errors, no break",
		err:       errors.Join(err1, err2, err3),
		want:      []error{err1, err2, err3},
		breakWhen: alwaysFalse,
	}, {
		desc:      "multiple joined errors, break early",
		err:       errors.Join(err1, err2, err3),
		want:      []error{err1, err2},
		breakWhen: equal(err3),
	},
}

func TestAll(t *testing.T) {
	for _, tc := range cases {
		f := func(t *testing.T) {
			t.Parallel()
			got := cfgerrors.All(tc.err)
			assertEqual(t, got, tc.want, tc.breakWhen)
		}
		t.Run(tc.desc, f)
	}
}

func BenchmarkAll(b *testing.B) {
	for _, bc := range cases {
		f := func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				for errSink = range cfgerrors.All(bc.err) {
					// deliberately empty
				}
			}
		}
		b.Run(bc.desc, f)
	}
}

var errSink error

var (
	err1 = errors.New("err1")
	err2 = errors.New("err2")
	err3 = errors.New("err3")
)

func assertEqual(
	t *testing.T,
	got iter.Seq[error],
	want []error,
	breakWhen func(error) bool,
) {
	t.Helper()
	var errs []error
	var i int
	for err := range got {
		if breakWhen(err) {
			return
		}
		errs = append(errs, err)
		if len(want) <= i {
			t.Fatalf("too many elements: got %v...; want %v", errs, want)
		}
		if err != want[i] {
			t.Fatalf("unexpected element: got %v...; want %v...", errs, want[:i+1])
		}
		i++
	}
	// i should now be equal to len(want)
	if i != len(want) {
		t.Fatalf("not enough elements: got %v; want %v...", errs, want)
	}
}

func alwaysFalse(_ error) bool {
	return false
}

func equal(target error) func(error) bool {
	return func(err error) bool {
		return err == target
	}
}

// In general, you don't want to assert on error messages;
// see https://go.dev/wiki/TestComments#test-error-semantics.
// This test only checks that the error message of each concrete error type is
// prefixed as desired.
func Test_that_error_messages_are_prefixed_by_package_name(t *testing.T) {
	errs := []error{
		&cfgerrors.UnacceptableOriginPatternError{Reason: "missing"},
		&cfgerrors.UnacceptableOriginPatternError{Value: "foo", Reason: "invalid"},
		&cfgerrors.UnacceptableOriginPatternError{Value: "null", Reason: "prohibited"},
		//
		&cfgerrors.UnacceptableMethodError{Value: "résumé", Reason: "invalid"},
		&cfgerrors.UnacceptableMethodError{Value: http.MethodConnect, Reason: "forbidden"},
		//
		&cfgerrors.UnacceptableHeaderNameError{Value: "résumé", Type: "request", Reason: "invalid"},
		&cfgerrors.UnacceptableHeaderNameError{Value: "Connection", Type: "request", Reason: "forbidden"},
		&cfgerrors.UnacceptableHeaderNameError{Value: "Origin", Type: "request", Reason: "prohibited"},
		&cfgerrors.UnacceptableHeaderNameError{Value: "résumé", Type: "response", Reason: "invalid"},
		&cfgerrors.UnacceptableHeaderNameError{Value: "Set-Cookie", Type: "response", Reason: "forbidden"},
		//
		&cfgerrors.MaxAgeOutOfBoundsError{Value: -2, Default: 5, Max: 86_400, Disable: -1},
		//
		&cfgerrors.IncompatibleOriginPatternError{Value: "*", Reason: "wildcard"},
		&cfgerrors.IncompatibleOriginPatternError{Value: "http://example.com", Reason: "insecure"},
		&cfgerrors.IncompatibleOriginPatternError{Value: "https://*.com", Reason: "psl"},
		&cfgerrors.IncompatibleOriginPatternError{Reason: "unknown"},
		//
		new(cfgerrors.IncompatibleWildcardResponseHeaderNameError),
	}
	const wantPrefix = "cors: "
	for _, err := range errs {
		if msg := err.Error(); !strings.HasPrefix(msg, wantPrefix) {
			t.Errorf("missing package-name prefix in %q", msg)
		}
	}
}

// comparability checks
var (
	_ map[cfgerrors.UnacceptableOriginPatternError]struct{}
	_ map[cfgerrors.UnacceptableMethodError]struct{}
	_ map[cfgerrors.UnacceptableHeaderNameError]struct{}
	_ map[cfgerrors.MaxAgeOutOfBoundsError]struct{}
	_ map[cfgerrors.IncompatibleOriginPatternError]struct{}
	_ map[cfgerrors.IncompatibleWildcardResponseHeaderNameError]struct{}
)
