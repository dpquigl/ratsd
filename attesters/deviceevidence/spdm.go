// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package deviceevidence

import (
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
)

// Field sizes/offsets below follow DSP0274 (SPDM spec) as reified in
// libspdm/include/industry_standard/spdm.h (spdm_message_header_t,
// spdm_measurement_block_common_header_t, spdm_measurement_block_dmtf_header_t,
// spdm_svh_header_t).
const (
	// spdmRespGetMeasurements is the RequestResponseCode for a GET_MEASUREMENTS
	// response (SPDM_MEASUREMENTS in libspdm).
	spdmRespGetMeasurements uint8 = 0x60

	// spdmMessageHeaderLen is sizeof(spdm_message_header_t): SPDMVersion,
	// RequestResponseCode, Param1, Param2.
	spdmMessageHeaderLen = 4

	// spdmMeasurementBlockCommonHeaderLen is sizeof(spdm_measurement_block_common_header_t):
	// Index, MeasurementSpecification, MeasurementSize (2 bytes LE).
	spdmMeasurementBlockCommonHeaderLen = 4

	// spdmMeasurementBlockDMTFHeaderLen is sizeof(spdm_measurement_block_dmtf_header_t):
	// DMTFSpecMeasurementValueType, DMTFSpecMeasurementValueSize (2 bytes LE).
	spdmMeasurementBlockDMTFHeaderLen = 3

	// spdmMeasurementSpecificationDMTF is SPDM_MEASUREMENT_SPECIFICATION_DMTF.
	spdmMeasurementSpecificationDMTF = 0x01

	spdmNonceSize     = 32 // SPDM_NONCE_SIZE
	spdmReqContextLen = 8  // SPDM_REQ_CONTEXT_SIZE

	// spdmVersion13 is SPDM_MESSAGE_VERSION_13: the RequesterContext trailer
	// on GET_MEASUREMENTS responses was added starting at this version.
	spdmVersion13 uint8 = 0x13

	// svhIDIANACBOR is SPDM_REGISTRY_ID_IANA_CBOR (spdm_svh_header_t.id) —
	// identifies an SVH-prefixed value whose manifest is IANA-CBOR-tagged.
	svhIDIANACBOR byte = 0x0A

	// cborTagCOSESign1 is the one-byte encoding of CBOR tag 18 (COSE_Sign1):
	// major type 6 (0b110_xxxxx) with additional info 18 (0b10010).
	cborTagCOSESign1 byte = 0xD2
)

// measurementBlock is a single parsed entry from an SPDM GET_MEASUREMENTS
// response's MeasurementRecord.
type measurementBlock struct {
	Index    uint8
	Spec     uint8
	DMTFType uint8  // raw byte, NOT pre-masked; see measType/measFormat.
	Value    []byte // DMTFSpecMeasurementValue (DMTF blocks) or the raw measurement value (non-DMTF).
	Raw      []byte // the full block (common header + DMTF header + value), as it appeared on the wire.
}

// measurementsResponse is a parsed SPDM GET_MEASUREMENTS response.
type measurementsResponse struct {
	SPDMVersion uint8
	Blocks      []measurementBlock
	Nonce       []byte
	Opaque      []byte
	Signature   []byte
}

// measType extracts the DMTF measurement value type (low 7 bits) from a raw
// DMTFSpecMeasurementValueType byte.
//
// CRITICAL: always mask before comparing against a well-known type constant.
// The DAT's structured-manifest type is 0x0A, but on the wire index 0xFD's
// format bit (bit 7) is set for Bitstream, so the byte actually observed is
// 0x8A. Comparing the raw byte to 0x0A will silently miss every real DAT
// block.
func measType(t uint8) uint8 { return t & 0x7F }

// measFormat extracts the DMTF measurement value format bit: 0 = Digest,
// 1 = Bitstream.
func measFormat(t uint8) uint8 { return (t & 0x80) >> 7 }

// findBlock returns the first measurement block with the given index.
func findBlock(blocks []measurementBlock, idx uint8) (*measurementBlock, bool) {
	for i := range blocks {
		if blocks[i].Index == idx {
			return &blocks[i], true
		}
	}
	return nil, false
}

// parseMeasurementsResponse parses a raw SPDM GET_MEASUREMENTS response
// (DSP0274). Every cursor advance is bounds-checked; malformed/truncated
// input yields an error, never a panic.
func parseMeasurementsResponse(b []byte) (*measurementsResponse, error) {
	if len(b) < spdmMessageHeaderLen {
		return nil, fmt.Errorf("measurements response too short: %d bytes, need at least %d for header",
			len(b), spdmMessageHeaderLen)
	}
	version := b[0]
	code := b[1]
	if code != spdmRespGetMeasurements {
		return nil, fmt.Errorf("unexpected RequestResponseCode 0x%02x, want GET_MEASUREMENTS response 0x%02x",
			code, spdmRespGetMeasurements)
	}

	off := spdmMessageHeaderLen

	// NumberOfBlocks (1 byte) + MeasurementRecordLength (3 bytes LE).
	if len(b) < off+4 {
		return nil, fmt.Errorf("truncated before NumberOfBlocks/MeasurementRecordLength: have %d bytes at offset %d, need 4",
			len(b)-off, off)
	}
	numBlocks := b[off]
	off++
	recLen := uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16
	off += 3

	if uint64(off)+uint64(recLen) > uint64(len(b)) {
		return nil, fmt.Errorf("MeasurementRecordLength %d exceeds remaining buffer (%d bytes available at offset %d)",
			recLen, len(b)-off, off)
	}
	rec := b[off : off+int(recLen)]
	off += int(recLen)

	blocks, err := parseMeasurementBlocks(rec, numBlocks)
	if err != nil {
		return nil, fmt.Errorf("parsing measurement record: %w", err)
	}

	// Nonce[32].
	if len(b) < off+spdmNonceSize {
		return nil, fmt.Errorf("truncated before Nonce: have %d bytes at offset %d, need %d",
			len(b)-off, off, spdmNonceSize)
	}
	nonce := b[off : off+spdmNonceSize]
	off += spdmNonceSize

	// OpaqueLength (2 bytes LE) + OpaqueData.
	if len(b) < off+2 {
		return nil, fmt.Errorf("truncated before OpaqueLength: have %d bytes at offset %d, need 2",
			len(b)-off, off)
	}
	opaqueLen := uint16(b[off]) | uint16(b[off+1])<<8
	off += 2
	if uint64(off)+uint64(opaqueLen) > uint64(len(b)) {
		return nil, fmt.Errorf("OpaqueLength %d exceeds remaining buffer (%d bytes available at offset %d)",
			opaqueLen, len(b)-off, off)
	}
	opaque := b[off : off+int(opaqueLen)]
	off += int(opaqueLen)

	// RequesterContext[8], present only for SPDM >= 1.3.
	if version >= spdmVersion13 {
		if len(b) < off+spdmReqContextLen {
			return nil, fmt.Errorf("truncated before RequesterContext: have %d bytes at offset %d, need %d",
				len(b)-off, off, spdmReqContextLen)
		}
		off += spdmReqContextLen
	}

	// Signature is whatever remains; its length depends on the negotiated
	// asymmetric algorithm and isn't self-describing on the wire, but as the
	// trailing field this is safe (may legitimately be empty/zero-length if
	// GENERATE_SIGNATURE wasn't requested).
	signature := b[off:]

	return &measurementsResponse{
		SPDMVersion: version,
		Blocks:      blocks,
		Nonce:       nonce,
		Opaque:      opaque,
		Signature:   signature,
	}, nil
}

// parseMeasurementBlocks parses the MeasurementRecord portion of a
// GET_MEASUREMENTS response into n measurement blocks.
func parseMeasurementBlocks(rec []byte, n uint8) ([]measurementBlock, error) {
	blocks := make([]measurementBlock, 0, n)
	off := 0

	for i := 0; i < int(n); i++ {
		if off+spdmMeasurementBlockCommonHeaderLen > len(rec) {
			return nil, fmt.Errorf("block %d: truncated common header at offset %d (record len %d)",
				i, off, len(rec))
		}
		index := rec[off]
		spec := rec[off+1]
		measSize := uint16(rec[off+2]) | uint16(rec[off+3])<<8
		blockStart := off
		off += spdmMeasurementBlockCommonHeaderLen

		if off+int(measSize) > len(rec) {
			return nil, fmt.Errorf("block %d: MeasurementSize %d exceeds remaining record (%d bytes at offset %d)",
				i, measSize, len(rec)-off, off)
		}
		value := rec[off : off+int(measSize)]
		off += int(measSize)

		blk := measurementBlock{
			Index: index,
			Spec:  spec,
			Raw:   rec[blockStart:off],
		}

		if spec&spdmMeasurementSpecificationDMTF != 0 {
			if len(value) < spdmMeasurementBlockDMTFHeaderLen {
				return nil, fmt.Errorf("block %d: DMTF sub-header truncated: %d bytes, need %d",
					i, len(value), spdmMeasurementBlockDMTFHeaderLen)
			}
			dmtfType := value[0]
			dmtfSize := uint16(value[1]) | uint16(value[2])<<8
			if measSize != uint16(spdmMeasurementBlockDMTFHeaderLen)+dmtfSize {
				return nil, fmt.Errorf("block %d: MeasurementSize %d != %d+DMTFSpecMeasurementValueSize %d",
					i, measSize, spdmMeasurementBlockDMTFHeaderLen, dmtfSize)
			}
			if spdmMeasurementBlockDMTFHeaderLen+int(dmtfSize) > len(value) {
				return nil, fmt.Errorf("block %d: DMTFSpecMeasurementValueSize %d exceeds remaining block (%d bytes)",
					i, dmtfSize, len(value)-spdmMeasurementBlockDMTFHeaderLen)
			}
			blk.DMTFType = dmtfType
			blk.Value = value[spdmMeasurementBlockDMTFHeaderLen : spdmMeasurementBlockDMTFHeaderLen+int(dmtfSize)]
		} else {
			blk.Value = value
		}

		blocks = append(blocks, blk)
	}

	return blocks, nil
}

// parseSVH decodes an SPDM Standards Vendor Header: a 1-byte registry id, a
// 1-byte vendor-id length, that many bytes of vendor id, and the remainder as
// the (vendor-defined) manifest. It is generic, not fixed at 3 bytes: only
// the IANA-CBOR registry (id 0x0A) happens to carry a 1-byte vendor id in
// this plugin's usage.
func parseSVH(v []byte) (id byte, vendorID []byte, manifest []byte, err error) {
	if len(v) < 2 {
		return 0, nil, nil, fmt.Errorf("SVH truncated: %d bytes, need at least 2 for id/vendorIDLen", len(v))
	}
	id = v[0]
	vendorIDLen := int(v[1])
	if len(v) < 2+vendorIDLen {
		return 0, nil, nil, fmt.Errorf("SVH truncated: vendorIDLen %d exceeds remaining %d bytes",
			vendorIDLen, len(v)-2)
	}
	vendorID = v[2 : 2+vendorIDLen]
	manifest = v[2+vendorIDLen:]
	return id, vendorID, manifest, nil
}

// validateCOSESign1 confirms b is CBOR tag 18 (COSE_Sign1) wrapping a
// 4-element array (protected header, unprotected header, payload, signature).
// It performs no cryptographic verification of the signature itself — that is
// the downstream verifier's job, not this plugin's.
func validateCOSESign1(b []byte) error {
	if len(b) < 1 {
		return fmt.Errorf("COSE_Sign1 manifest is empty")
	}
	if b[0] != cborTagCOSESign1 {
		return fmt.Errorf("manifest does not start with CBOR tag 18 (COSE_Sign1): got byte 0x%02x", b[0])
	}
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(b[1:], &arr); err != nil {
		return fmt.Errorf("decoding COSE_Sign1 array: %w", err)
	}
	if len(arr) != 4 {
		return fmt.Errorf("COSE_Sign1 array has %d elements, want 4 (protected/unprotected/payload/signature)",
			len(arr))
	}
	return nil
}
