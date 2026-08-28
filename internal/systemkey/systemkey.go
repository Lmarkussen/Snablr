// Package systemkey derives the offline Windows SYSTEM hive boot key.
// It resolves Select\Current and reads the LSA key class metadata from the
// selected control set. It does not parse credentials or modify the hive.
package systemkey

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"snablr/internal/registryhive"
)

var (
	ErrMissingSelect     = errors.New("SYSTEM hive Select key is missing")
	ErrMissingCurrent    = errors.New("SYSTEM hive Select\\Current value is missing")
	ErrInvalidCurrent    = errors.New("SYSTEM hive Select\\Current value is invalid")
	ErrMissingControlSet = errors.New("SYSTEM hive control set is missing")
	ErrMissingControl    = errors.New("SYSTEM hive Control key is missing")
	ErrMissingLSA        = errors.New("SYSTEM hive Lsa key is missing")
	ErrMissingFragment   = errors.New("SYSTEM hive LSA class fragment is missing")
	ErrMissingClass      = errors.New("SYSTEM hive LSA class metadata is missing")
	ErrInvalidFragment   = errors.New("SYSTEM hive LSA class fragments are invalid")
)

var permutation = [...]int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

// Result contains the derived boot key and the selected control-set number.
// BootKey is intentionally not formatted or logged by this package.
type Result struct {
	BootKey    [16]byte
	ControlSet uint32
}

// Derive derives the 16-byte boot key from an already-open SYSTEM hive.
func Derive(hive *registryhive.Reader) (Result, error) {
	if hive == nil {
		return Result{}, fmt.Errorf("%w: nil hive", ErrInvalidCurrent)
	}
	selectKey, err := hive.OpenKey("Select")
	if err != nil {
		return Result{}, fmt.Errorf("%w", ErrMissingSelect)
	}
	currentValue, err := selectKey.Value("Current")
	if err != nil {
		return Result{}, fmt.Errorf("%w", ErrMissingCurrent)
	}
	current, err := currentValue.DWORD()
	if err != nil || current == 0 || current > 999 {
		return Result{}, fmt.Errorf("%w", ErrInvalidCurrent)
	}
	controlSet := fmt.Sprintf("ControlSet%03d", current)
	if _, err := hive.OpenKey(controlSet); err != nil {
		return Result{}, fmt.Errorf("%w: %s", ErrMissingControlSet, controlSet)
	}
	if _, err := hive.OpenKey(controlSet + `\Control`); err != nil {
		return Result{}, fmt.Errorf("%w: %s", ErrMissingControl, controlSet)
	}
	if _, err := hive.OpenKey(controlSet + `\Control\Lsa`); err != nil {
		return Result{}, fmt.Errorf("%w: %s", ErrMissingLSA, controlSet)
	}

	var encoded [32]byte
	encodedLen := 0
	for _, name := range []string{"JD", "Skew1", "GBG", "Data"} {
		key, err := hive.OpenKey(controlSet + `\Control\Lsa\` + name)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %s\\Control\\Lsa\\%s class", ErrMissingFragment, controlSet, name)
		}
		className, err := key.ClassName()
		if err != nil {
			return Result{}, fmt.Errorf("%w: %s\\Control\\Lsa\\%s class", ErrInvalidFragment, controlSet, name)
		}
		className = strings.Trim(className, " \t\r\n\x00")
		if className == "" {
			return Result{}, fmt.Errorf("%w: %s\\Control\\Lsa\\%s class", ErrMissingClass, controlSet, name)
		}
		if encodedLen+len(className) > len(encoded) {
			return Result{}, fmt.Errorf("%w: fragment data is too long", ErrInvalidFragment)
		}
		copy(encoded[encodedLen:], className)
		encodedLen += len(className)
	}
	if encodedLen != len(encoded) {
		return Result{}, fmt.Errorf("%w: expected 32 hexadecimal characters", ErrInvalidFragment)
	}
	decoded := make([]byte, 16)
	if _, err := hex.Decode(decoded, encoded[:]); err != nil {
		return Result{}, fmt.Errorf("%w: non-hexadecimal class data", ErrInvalidFragment)
	}
	var result Result
	result.ControlSet = current
	for i, source := range permutation {
		result.BootKey[i] = decoded[source]
	}
	for i := range decoded {
		decoded[i] = 0
	}
	for i := range encoded {
		encoded[i] = 0
	}
	return result, nil
}
