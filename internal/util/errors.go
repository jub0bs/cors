package util

import (
	"fmt"
	"io"
	"strconv"
)

const pkgName = "cors"

// NewError is similar to [errors.New],
// but the message of the resulting error is prefixed with "cors: ".
func NewError(text string) error {
	return &configError{
		pkgName: pkgName,
		msg:     text,
	}
}

// Errorf is similar to [fmt.Errorf],
// but the message of the resulting error is prefixed with "cors: ".
func Errorf(format string, a ...any) error {
	return &configError{
		pkgName: pkgName,
		msg:     fmt.Sprintf(format, a...),
	}
}

type configError struct {
	pkgName string
	msg     string
}

func (e *configError) Error() string {
	return fmt.Sprintf("%s: %s", e.pkgName, e.msg)
}

// SetPkgName sets the package name mentioned in the error's message to name.
// SetPkgName exists only to allow github.com/jub0bs/fcors to substitute
// "fcors" for "cors" in its own error messages.
func (e *configError) SetPkgName(name string) {
	e.pkgName = name
}

// InvalidOriginPatternErr returns an error about invalid origin pattern str.
func InvalidOriginPatternErr(str string) error {
	return Errorf("invalid origin pattern %q", str)
}

// Join joins the elements of strs in a human-friendly way
// and writes the result to w.
func Join(w io.StringWriter, strs []string) {
	// Errors are deliberately ignored.
	switch len(strs) {
	case 0:
	case 1:
		w.WriteString(strconv.Quote(strs[0]))
	case 2:
		w.WriteString(strconv.Quote(strs[0]))
		w.WriteString(" and ")
		w.WriteString(strconv.Quote(strs[1]))
	default:
		w.WriteString(strconv.Quote(strs[0]))
		for i := 1; i < len(strs)-1; i++ {
			w.WriteString(", ")
			w.WriteString(strconv.Quote(strs[i]))
		}
		w.WriteString(", and ")
		w.WriteString(strconv.Quote(strs[len(strs)-1]))
	}
}
