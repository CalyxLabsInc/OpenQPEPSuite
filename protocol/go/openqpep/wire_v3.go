// Package openqpep provides the Go Production Candidate 1.1.0 (v1.1.0-pc) conformance port (CPOSLS-1.0).
package openqpep

import "bytes"

var (
	WireMagicV3  = []byte{0x89, 'Q', 'P', 'E', 0x03, 0x00}
	WireMagicV31 = []byte{0x89, 'Q', 'P', 'E', 0x03, 0x01}
)

func IsSupportedWireMagic(frame []byte) bool {
	if len(frame) < 6 {
		return false
	}
	hdr := frame[:6]
	return bytes.Equal(hdr, WireMagicV31) || bytes.Equal(hdr, WireMagicV3)
}
