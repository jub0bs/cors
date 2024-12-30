package util

import (
	"fmt"
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
