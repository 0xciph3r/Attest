package verifier

import (
	"bytes"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// decode strictly unmarshals a TPM structure: the input must be exactly the
// canonical encoding of the decoded value (no trailing bytes), and parser
// panics on hostile input are converted to errors.
func decode[T tpm2.Marshallable, P interface {
	*T
	tpm2.Unmarshallable
}](b []byte) (v *T, err error) {
	defer func() {
		if r := recover(); r != nil {
			v, err = nil, fmt.Errorf("decode panic: %v", r)
		}
	}()
	v, err = tpm2.Unmarshal[T, P](b)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(tpm2.Marshal(*v), b) {
		return nil, fmt.Errorf("non-canonical or trailing bytes")
	}
	return v, nil
}
