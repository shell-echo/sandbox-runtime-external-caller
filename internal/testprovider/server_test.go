package testprovider

import (
	"bytes"
	"testing"
)

func TestSyntheticShellResponseAcceptsOnlyBoundedRoundTripCommand(t *testing.T) {
	marker := []byte("0123456789abcdef0123456789abcdef")
	command := append([]byte("printf '\\nSRC-ROUNDTRIP-"), marker...)
	command = append(command, []byte("\\n'\n")...)
	response, ok := syntheticShellResponse(command)
	if !ok || !bytes.Equal(response, append(append([]byte("\nSRC-ROUNDTRIP-"), marker...), '\n')) {
		t.Fatalf("response = %q, accepted %t", response, ok)
	}
	for _, invalid := range [][]byte{
		[]byte("printf 'arbitrary'\n"),
		[]byte("printf '\\nSRC-ROUNDTRIP-not-hex-not-hex-not-hex-not-hex!\\n'\n"),
		append(append([]byte(nil), command...), 'x'),
	} {
		if response, ok := syntheticShellResponse(invalid); ok || response != nil {
			t.Fatalf("invalid command accepted: %q", invalid)
		}
	}
}
