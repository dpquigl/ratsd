// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package deviceevidence

import (
	"bytes"
	"encoding/binary"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
)

// buildDMTFBlock builds one DMTF-specification measurement block: common
// header (Index, Spec, MeasurementSize) followed by the DMTF sub-header
// (DMTFSpecMeasurementValueType, DMTFSpecMeasurementValueSize) and the value.
func buildDMTFBlock(index, dmtfType byte, value []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(index)
	buf.WriteByte(0x01) // MeasurementSpecification: DMTF
	measSize := uint16(spdmMeasurementBlockDMTFHeaderLen + len(value))
	_ = binary.Write(&buf, binary.LittleEndian, measSize)
	buf.WriteByte(dmtfType)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(value)))
	buf.Write(value)
	return buf.Bytes()
}

// buildMeasurementsResponse assembles a full synthetic GET_MEASUREMENTS
// response: header, NumberOfBlocks/MeasurementRecordLength, the concatenated
// blocks, a 32-byte nonce, a zero-length OpaqueData, a RequesterContext (for
// version >= 1.3), and trailing signature bytes.
func buildMeasurementsResponse(version byte, blocks [][]byte, nonce [32]byte, signature []byte) []byte {
	var rec bytes.Buffer
	for _, b := range blocks {
		rec.Write(b)
	}

	var buf bytes.Buffer
	buf.WriteByte(version)
	buf.WriteByte(spdmRespGetMeasurements)
	buf.WriteByte(0x00) // param1
	buf.WriteByte(0x00) // param2
	buf.WriteByte(byte(len(blocks)))
	recLen := uint32(rec.Len())
	buf.WriteByte(byte(recLen))
	buf.WriteByte(byte(recLen >> 8))
	buf.WriteByte(byte(recLen >> 16))
	buf.Write(rec.Bytes())
	buf.Write(nonce[:])
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0)) // OpaqueLength
	if version >= spdmVersion13 {
		buf.Write(make([]byte, spdmReqContextLen))
	}
	buf.Write(signature)
	return buf.Bytes()
}

func TestParseMeasurementsResponse_RoundTrip(t *testing.T) {
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	sig := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	block1Value := []byte{0x01, 0x02, 0x03, 0x04}
	block2Value := []byte{0x05, 0x06}

	blocks := [][]byte{
		buildDMTFBlock(0x01, 0x01, block1Value), // MutableFirmware, digest format
		buildDMTFBlock(0x02, 0x86, block2Value), // type 0x06, bitstream format bit set
	}

	resp := buildMeasurementsResponse(0x14, blocks, nonce, sig)

	mr, err := parseMeasurementsResponse(resp)
	if err != nil {
		t.Fatalf("parseMeasurementsResponse: %v", err)
	}

	if mr.SPDMVersion != 0x14 {
		t.Errorf("SPDMVersion = 0x%02x, want 0x14", mr.SPDMVersion)
	}
	if len(mr.Blocks) != 2 {
		t.Fatalf("len(Blocks) = %d, want 2", len(mr.Blocks))
	}
	if mr.Blocks[0].Index != 0x01 || mr.Blocks[0].DMTFType != 0x01 || !bytes.Equal(mr.Blocks[0].Value, block1Value) {
		t.Errorf("block 0 = %+v, want index=1 type=0x01 value=%x", mr.Blocks[0], block1Value)
	}
	if mr.Blocks[1].Index != 0x02 || mr.Blocks[1].DMTFType != 0x86 || !bytes.Equal(mr.Blocks[1].Value, block2Value) {
		t.Errorf("block 1 = %+v, want index=2 type=0x86 value=%x", mr.Blocks[1], block2Value)
	}
	if got := measType(mr.Blocks[1].DMTFType); got != 0x06 {
		t.Errorf("measType(0x86) = 0x%02x, want 0x06", got)
	}
	if got := measFormat(mr.Blocks[1].DMTFType); got != 1 {
		t.Errorf("measFormat(0x86) = %d, want 1", got)
	}
	if !bytes.Equal(mr.Nonce, nonce[:]) {
		t.Errorf("Nonce = %x, want %x", mr.Nonce, nonce[:])
	}
	if len(mr.Opaque) != 0 {
		t.Errorf("Opaque = %x, want empty", mr.Opaque)
	}
	if !bytes.Equal(mr.Signature, sig) {
		t.Errorf("Signature = %x, want %x", mr.Signature, sig)
	}
}

func TestDATBlock_ExtractsManifestAfterSVH(t *testing.T) {
	// A well-formed 4-element CBOR array: protected/unprotected/payload/signature.
	arr, err := cbor.Marshal([]interface{}{"protected", "unprotected", "payload", "signature"})
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	manifest := append([]byte{cborTagCOSESign1}, arr...)
	svh := []byte{svhIDIANACBOR, 0x01, cborTagCOSESign1}
	value := append(append([]byte{}, svh...), manifest...)

	var nonce [32]byte
	blocks := [][]byte{buildDMTFBlock(datIndex, 0x8A, value)}
	resp := buildMeasurementsResponse(0x14, blocks, nonce, nil)

	mr, err := parseMeasurementsResponse(resp)
	if err != nil {
		t.Fatalf("parseMeasurementsResponse: %v", err)
	}

	blk, found := findBlock(mr.Blocks, datIndex)
	if !found {
		t.Fatal("block 0xFD not found")
	}
	// The critical gotcha: the on-wire byte is 0x8A (bitstream format bit
	// set), not 0x0A. Dispatch must mask before comparing.
	if blk.DMTFType != 0x8A {
		t.Fatalf("blk.DMTFType = 0x%02x, want raw (unmasked) 0x8A", blk.DMTFType)
	}
	if measType(blk.DMTFType) != datMeasurementType {
		t.Fatalf("measType(0x%02x) = 0x%02x, want 0x%02x", blk.DMTFType, measType(blk.DMTFType), datMeasurementType)
	}

	got, err := buildDAT(blk)
	if err != nil {
		t.Fatalf("buildDAT: %v", err)
	}
	if got == nil {
		t.Fatal("buildDAT returned nil manifest for a well-formed DAT block")
	}
	if !bytes.Equal(got, manifest) {
		t.Errorf("buildDAT manifest = %x, want %x (exactly the bytes after the 3-byte SVH)", got, manifest)
	}
}

func TestBuildDAT_WrongVendor_IsNotADAT(t *testing.T) {
	// SVH names IANA-CBOR but a vendor id other than COSE_Sign1 (0xD2):
	// buildDAT must decline (nil, nil), not error, so the caller falls
	// through to Concise Evidence.
	value := []byte{svhIDIANACBOR, 0x01, 0x99}
	blk := &measurementBlock{Index: datIndex, DMTFType: 0x8A, Value: value}

	got, err := buildDAT(blk)
	if err != nil {
		t.Fatalf("buildDAT: unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("buildDAT = %x, want nil (not a recognized DAT)", got)
	}
}

func TestNonDATMeasurementType_DoesNotDispatchAsDAT(t *testing.T) {
	var nonce [32]byte
	blocks := [][]byte{buildDMTFBlock(datIndex, 0x84, []byte{0x00})}
	resp := buildMeasurementsResponse(0x14, blocks, nonce, nil)

	mr, err := parseMeasurementsResponse(resp)
	if err != nil {
		t.Fatalf("parseMeasurementsResponse: %v", err)
	}

	blk, found := findBlock(mr.Blocks, datIndex)
	if !found {
		t.Fatal("block 0xFD not found")
	}
	if measType(blk.DMTFType) == datMeasurementType {
		t.Fatalf("measType(0x84) unexpectedly matched DAT type 0x%02x", datMeasurementType)
	}
	if measType(blk.DMTFType) != 0x04 {
		t.Errorf("measType(0x84) = 0x%02x, want 0x04", measType(blk.DMTFType))
	}
}

func TestNo0xFDBlock_FallsThroughToSPDMClaims(t *testing.T) {
	var nonce [32]byte
	blocks := [][]byte{buildDMTFBlock(0x01, 0x01, []byte{0x00})}
	resp := buildMeasurementsResponse(0x14, blocks, nonce, nil)

	mr, err := parseMeasurementsResponse(resp)
	if err != nil {
		t.Fatalf("parseMeasurementsResponse: %v", err)
	}
	if _, found := findBlock(mr.Blocks, datIndex); found {
		t.Fatal("unexpectedly found block 0xFD")
	}
}

func TestParseMeasurementsResponse_Truncated(t *testing.T) {
	var nonce [32]byte
	block := buildDMTFBlock(0x01, 0x01, []byte{0xAA})
	full := buildMeasurementsResponse(0x14, [][]byte{block}, nonce, []byte{0x01, 0x02})

	const headerLen = spdmMessageHeaderLen
	recLen := len(block)
	recordEnd := headerLen + 4 + recLen // offset right after the measurement record

	cases := []struct {
		name string
		b    []byte
	}{
		{"empty input", nil},
		{"header shorter than 4 bytes", full[:3]},
		{"missing NumberOfBlocks/MeasurementRecordLength", full[:headerLen+2]},
		{"truncated before Nonce", full[:recordEnd]},
		{"truncated before OpaqueLength", full[:recordEnd+16]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseMeasurementsResponse(tc.b); err == nil {
				t.Fatalf("expected an error, got nil")
			}
		})
	}

	// MeasurementRecordLength claims far more bytes than remain in the buffer.
	t.Run("MeasurementRecordLength exceeds buffer", func(t *testing.T) {
		bogus := append([]byte{}, full[:recordEnd]...)
		bogus[headerLen+1] = 0xFF
		bogus[headerLen+2] = 0xFF
		bogus[headerLen+3] = 0xFF
		if _, err := parseMeasurementsResponse(bogus); err == nil {
			t.Fatalf("expected an error, got nil")
		}
	})
}

func TestParseMeasurementBlocks_Malformed(t *testing.T) {
	t.Run("common header truncated", func(t *testing.T) {
		if _, err := parseMeasurementBlocks([]byte{0x01, 0x01}, 1); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("measurement size exceeds record", func(t *testing.T) {
		rec := []byte{0x01, 0x01, 0xFF, 0xFF} // MeasurementSize = 0xFFFF, no value follows
		if _, err := parseMeasurementBlocks(rec, 1); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("DMTF sub-header truncated", func(t *testing.T) {
		// Spec has the DMTF bit set; MeasurementSize=1 is too small to hold
		// the 3-byte DMTF sub-header.
		rec := []byte{0x01, 0x01, 0x01, 0x00, 0xAA}
		if _, err := parseMeasurementBlocks(rec, 1); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("MeasurementSize disagrees with DMTFSpecMeasurementValueSize", func(t *testing.T) {
		// Common header claims MeasurementSize=4, but the DMTF sub-header
		// claims a value size of 2 (i.e. it should have been 3+2=5).
		rec := []byte{0x01, 0x01, 0x04, 0x00, 0x02, 0x02, 0x00, 0xAA}
		if _, err := parseMeasurementBlocks(rec, 1); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("zero blocks requested", func(t *testing.T) {
		blocks, err := parseMeasurementBlocks([]byte{}, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(blocks) != 0 {
			t.Errorf("len(blocks) = %d, want 0", len(blocks))
		}
	})
}

func TestParseSVH_Truncated(t *testing.T) {
	if _, _, _, err := parseSVH([]byte{0x0A}); err == nil {
		t.Fatal("expected error for SVH shorter than 2 bytes")
	}
	if _, _, _, err := parseSVH([]byte{0x0A, 0x05, 0x01}); err == nil {
		t.Fatal("expected error when vendorIDLen exceeds remaining bytes")
	}
}

func TestParseSVH_WellFormed(t *testing.T) {
	id, vendorID, manifest, err := parseSVH([]byte{0x0A, 0x01, 0xD2, 0xAA, 0xBB})
	if err != nil {
		t.Fatalf("parseSVH: %v", err)
	}
	if id != 0x0A {
		t.Errorf("id = 0x%02x, want 0x0A", id)
	}
	if !bytes.Equal(vendorID, []byte{0xD2}) {
		t.Errorf("vendorID = %x, want d2", vendorID)
	}
	if !bytes.Equal(manifest, []byte{0xAA, 0xBB}) {
		t.Errorf("manifest = %x, want aabb", manifest)
	}
}

func TestValidateCOSESign1(t *testing.T) {
	arr, err := cbor.Marshal([]interface{}{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	good := append([]byte{cborTagCOSESign1}, arr...)
	if err := validateCOSESign1(good); err != nil {
		t.Errorf("validateCOSESign1(good) = %v, want nil", err)
	}

	if err := validateCOSESign1([]byte{}); err == nil {
		t.Error("validateCOSESign1(empty) = nil, want error")
	}
	if err := validateCOSESign1([]byte{0x00}); err == nil {
		t.Error("validateCOSESign1(wrong tag) = nil, want error")
	}

	arr3, err := cbor.Marshal([]interface{}{1, 2, 3})
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	badLen := append([]byte{cborTagCOSESign1}, arr3...)
	if err := validateCOSESign1(badLen); err == nil {
		t.Error("validateCOSESign1(3-element array) = nil, want error")
	}
}

// TestSPDMClaims_MatchesGoldenFieldSet is a structural sanity check against
// specs/resources/diag/manifest-exi.diag: the CDDL-derived, integer-keyed
// field set for the spdm-claims fallback bundle (§8.4/§8.5).
func TestSPDMClaims_MatchesGoldenFieldSet(t *testing.T) {
	sc := SPDMClaims{
		EATProfile: EATProfileSPDM,
		Measurements: map[uint8]MeasurementClaim{
			1: {ComponentType: 1, DigestMeasurement: &DigestMeasurement{Alg: "sha-384", Val: []byte{0x00}}},
			2: {ComponentType: 6, RawMeasurement: []byte{0x01}},
		},
		Certificates: map[uint8][]byte{0: {0x02}},
		VCA:          []byte{0x03},
	}

	encoded, err := cbor.Marshal(sc)
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}

	var decoded map[uint64]interface{}
	if err := cbor.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("cbor.Unmarshal: %v", err)
	}

	wantKeys := []uint64{265, 3802, 3803, 3804}
	for _, k := range wantKeys {
		if _, ok := decoded[k]; !ok {
			t.Errorf("encoded SPDMClaims missing key %d (see manifest-exi.diag)", k)
		}
	}

	// Nested maps decode generically as map[interface{}]interface{}, with
	// integer keys as uint64 (all labels here are non-negative).
	measurements, ok := decoded[3802].(map[interface{}]interface{})
	if !ok || len(measurements) != 2 {
		t.Fatalf("measurements = %#v, want a 2-entry map keyed by block index", decoded[3802])
	}

	digestEntry, ok := measurements[uint64(1)].(map[interface{}]interface{})
	if !ok {
		t.Fatalf("measurement entry 1 = %#v, want a map", measurements[uint64(1)])
	}
	for _, k := range []uint64{1, 2} {
		if _, ok := digestEntry[k]; !ok {
			t.Errorf("digest measurement entry missing key %d (see manifest-exi.diag)", k)
		}
	}
	digest, ok := digestEntry[uint64(2)].([]interface{})
	if !ok || len(digest) != 2 {
		t.Fatalf("digest-measurement claim = %#v, want a 2-element [alg, val] array", digestEntry[uint64(2)])
	}

	rawEntry, ok := measurements[uint64(2)].(map[interface{}]interface{})
	if !ok {
		t.Fatalf("measurement entry 2 = %#v, want a map", measurements[uint64(2)])
	}
	for _, k := range []uint64{1, 3} {
		if _, ok := rawEntry[k]; !ok {
			t.Errorf("raw measurement entry missing key %d (see manifest-exi.diag)", k)
		}
	}

	certs, ok := decoded[3803].(map[interface{}]interface{})
	if !ok {
		t.Fatalf("certificates = %#v, want a map keyed by cert slot", decoded[3803])
	}
	if _, ok := certs[uint64(0)]; !ok {
		t.Errorf("certificates missing default cert slot 0 (see manifest-exi.diag)")
	}
}
