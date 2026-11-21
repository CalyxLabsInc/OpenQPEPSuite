// Package openqpep provides the Go Release Candidate 1.0.0 (v1.0.0-rc) conformance port (CPOSLS-1.0).
// Hard Clean Break: Zero Backwards Compatibility with any legacy Production Candidate (-pc) or Beta frames.
package openqpep

import (
	"bytes"
	"errors"
)

const (
	QlxQ           = 3329
	ProtocolRC100  = "OpenQPEP/RC-1.0.0"
	MandatoryKDFV3 = 3
)

var (
	WireMagicV4        = []byte{0x89, 'Q', 'P', 'E', 0x04, 0x00}
	WireMagicV41       = []byte{0x89, 'Q', 'P', 'E', 0x04, 0x01}
	LegacyWireMagicV3  = []byte{0x89, 'Q', 'P', 'E', 0x03, 0x00}
	LegacyWireMagicV31 = []byte{0x89, 'Q', 'P', 'E', 0x03, 0x01}

	ErrLegacyProtocol = errors.New("QPEPLegacyProtocolError: legacy -pc or -beta wire format rejected in Release Candidate v1.0.0")
	ErrInvalidMagic   = errors.New("QPEPWireFormatError: invalid OpenQPEP Wire Format v4 magic")
)

func IsSupportedWireMagic(frame []byte) bool {
	if len(frame) < 6 {
		return false
	}
	hdr := frame[:6]
	return bytes.Equal(hdr, WireMagicV41) || bytes.Equal(hdr, WireMagicV4)
}

func ValidateWireFrameV4(frame []byte) error {
	if len(frame) < 6 {
		return ErrInvalidMagic
	}
	hdr := frame[:6]
	if bytes.Equal(hdr, LegacyWireMagicV3) || bytes.Equal(hdr, LegacyWireMagicV31) {
		return ErrLegacyProtocol
	}
	if !IsSupportedWireMagic(frame) {
		return ErrInvalidMagic
	}
	return nil
}
