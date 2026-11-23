// Package openqpep provides the Go Official Release 1.1.0 (v1.1.0) conformance port (CPOSLS-1.0).
// Wire Format v5/v5.1 compatible with OpenQPEP Official Releases 1.0.x+; zero compatibility with legacy -rc, -pc, or -beta frames.
package openqpep

import (
	"crypto/subtle"
	"errors"
)

const (
	QlxQ            = 3329
	ProtocolVersion = "OpenQPEP/1.1.0"
	MandatoryKDFV4  = 4
)

var (
	WireMagicV5        = []byte{0x89, 'Q', 'P', 'E', 0x05, 0x00}
	WireMagicV51       = []byte{0x89, 'Q', 'P', 'E', 0x05, 0x01}
	LegacyWireMagicV4  = []byte{0x89, 'Q', 'P', 'E', 0x04, 0x00}
	LegacyWireMagicV41 = []byte{0x89, 'Q', 'P', 'E', 0x04, 0x01}
	LegacyWireMagicV3  = []byte{0x89, 'Q', 'P', 'E', 0x03, 0x00}
	LegacyWireMagicV31 = []byte{0x89, 'Q', 'P', 'E', 0x03, 0x01}

	ErrLegacyProtocol = errors.New("QPEPLegacyProtocolError: legacy -rc, -pc, or -beta wire format rejected in Official Release 1.1.0")
	ErrInvalidMagic   = errors.New("QPEPWireFormatError: invalid OpenQPEP Official Wire Format v5 magic")
)

func IsSupportedWireMagic(frame []byte) bool {
	if len(frame) < 6 {
		return false
	}
	hdr := frame[:6]
	return subtle.ConstantTimeCompare(hdr, WireMagicV51) == 1 || subtle.ConstantTimeCompare(hdr, WireMagicV5) == 1
}

func ValidateWireFrameV5(frame []byte) error {
	if len(frame) < 6 {
		return ErrInvalidMagic
	}
	hdr := frame[:6]
	if subtle.ConstantTimeCompare(hdr, LegacyWireMagicV4) == 1 ||
		subtle.ConstantTimeCompare(hdr, LegacyWireMagicV41) == 1 ||
		subtle.ConstantTimeCompare(hdr, LegacyWireMagicV3) == 1 ||
		subtle.ConstantTimeCompare(hdr, LegacyWireMagicV31) == 1 ||
		(hdr[0] == 0x89 && hdr[1] == 'Q' && hdr[2] == 'P' && hdr[3] == 'E' && (hdr[4] == 0x01 || hdr[4] == 0x02)) {
		return ErrLegacyProtocol
	}
	if !IsSupportedWireMagic(frame) {
		return ErrInvalidMagic
	}
	return nil
}
