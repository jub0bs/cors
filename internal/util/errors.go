package util

import (
	"errors"
	"fmt"
)

const pkgName = "cors"

// NewError is similar to [errors.New],
// but the message of the resulting error is prefixed with "cors: ".
func NewError(text string) error {
	return errors.New(pkgName + ": " + text)
}

// Errorf is similar to [fmt.Errorf],
// but the message of the resulting error is prefixed with "cors: ".
func Errorf(format string, a ...any) error {
	return fmt.Errorf(pkgName+": "+format, a...)
}

// InvalidOriginPatternErr returns an error about invalid origin pattern str.
func InvalidOriginPatternErr(str string) error {
	return Errorf("invalid origin pattern %q", str)
}
