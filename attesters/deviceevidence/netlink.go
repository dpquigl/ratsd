// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package deviceevidence

import (
	"fmt"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

const (
	familyName    = "device-evidence"
	familyVersion = 1

	// Commands (device-evidence.yaml operations, 1-based order)
	cmdRead     uint8 = 1
	cmdValidate uint8 = 2

	// Attribute IDs for the object attribute set (device-evidence.yaml order)
	attrType     uint16 = 1
	attrTypeMask uint16 = 2
	// attrFlags uint16 = 3  (unused in requests for now)
	attrSubsys     uint16 = 4
	attrDevName    uint16 = 5
	attrNonce      uint16 = 6
	attrGeneration uint16 = 7
	// attrCount uint16 = 8  (TSM refresh-event count; unused here)
	attrLength uint16 = 9
	attrVal    uint16 = 10

	// subsysPCI is the device subsystem for PCIe TDIs.
	subsysPCI = "pci"

	// Evidence object type IDs, matching enum device_evidence_type in
	// include/uapi/linux/device-evidence.h (devsec/tsm kernel branch).
	//
	// Exported so other RATSd sub-attester plugins (e.g. tdispclaims) sharing
	// this netlink family can identify the objects they need without
	// duplicating the family/attribute plumbing in this file.
	EvTypeCert0        uint32 = 0
	EvTypeCert1        uint32 = 1
	EvTypeCert2        uint32 = 2
	EvTypeCert3        uint32 = 3
	EvTypeCert4        uint32 = 4
	EvTypeCert5        uint32 = 5
	EvTypeCert6        uint32 = 6
	EvTypeCert7        uint32 = 7
	EvTypeVCA          uint32 = 8
	EvTypeMeasurements uint32 = 9
	EvTypeReport       uint32 = 10

	// evidenceTypeFlagAll requests cert0–cert7, vca, measurements, and report
	// (11 evidence types, one bit per type), matching
	// DEVICE_EVIDENCE_TYPE_FLAG_MASK.
	evidenceTypeFlagAll uint32 = 0x7FF
)

// EvTypeCerts is EvTypeCert0..EvTypeCert7 in slot order.
var EvTypeCerts = [8]uint32{
	EvTypeCert0, EvTypeCert1, EvTypeCert2, EvTypeCert3,
	EvTypeCert4, EvTypeCert5, EvTypeCert6, EvTypeCert7,
}

// EvidenceObject is a single (reassembled) evidence object returned by the kernel.
type EvidenceObject struct {
	Type uint32
	Val  []byte
}

// ReadResult is the outcome of a read: the reassembled evidence objects plus the
// evidence generation reported by the kernel (0 if none was reported).
type ReadResult struct {
	Objects    []EvidenceObject
	Generation uint32
}

// Object returns the reassembled evidence object of the given type, if
// present. It linear-scans Objects, which is kept as the authoritative,
// order-preserving representation (other code/debug output may depend on its
// shape); the type-count per read is small (at most 11 today) so this is
// cheap.
func (r *ReadResult) Object(t uint32) ([]byte, bool) {
	if r == nil {
		return nil, false
	}
	for _, o := range r.Objects {
		if o.Type == t {
			return o.Val, true
		}
	}
	return nil, false
}

// genetlinkDial is a thin wrapper so deviceevidence.go can probe availability
// without importing the genetlink package directly.
func genetlinkDial() (*genetlink.Conn, error) {
	return genetlink.Dial(nil)
}

// FamilyAvailable reports whether the device-evidence generic netlink family
// is resolvable, i.e. the devsec/tsm kernel module is loaded. Exported so
// other RATSd sub-attester plugins sharing this family (e.g. tdispclaims) can
// reuse the same probe in their own GetSupportedFormats instead of
// duplicating the dial/GetFamily logic.
func FamilyAvailable() error {
	conn, err := genetlinkDial()
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.GetFamily(familyName)
	return err
}

// ReadEvidence opens a generic netlink socket, resolves the device-evidence
// family, and issues a 'read' dump request for the device identified by bdf
// with the given nonce. Large evidence objects may be split across several dump
// messages (each preceded by its total length); this function reassembles the
// ordered 'val' chunks per object and captures the evidence generation.
//
// Requires CAP_NET_ADMIN. Blocks the calling goroutine.
func ReadEvidence(bdf string, nonce []byte) (*ReadResult, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("opening generic netlink socket (CAP_NET_ADMIN required): %w", err)
	}
	defer conn.Close()

	family, err := conn.GetFamily(familyName)
	if err != nil {
		return nil, fmt.Errorf("resolving %q netlink family (devsec/tsm kernel required): %w",
			familyName, err)
	}

	// Build request attributes: type-mask, subsys, dev-name (NUL-terminated), nonce.
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(attrTypeMask, evidenceTypeFlagAll)
	ae.Bytes(attrSubsys, []byte(subsysPCI+"\x00"))
	ae.Bytes(attrDevName, []byte(bdf+"\x00"))
	ae.Bytes(attrNonce, nonce)

	attrData, err := ae.Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding netlink request attributes: %w", err)
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: cmdRead,
			Version: familyVersion,
		},
		Data: attrData,
	}

	msgs, err := conn.Execute(req, family.ID, netlink.Request|netlink.Dump)
	if err != nil {
		return nil, fmt.Errorf("executing device-evidence read dump: %w", err)
	}

	// Reassemble chunks per evidence type, preserving first-seen order.
	type partial struct {
		length    uint32
		hasLength bool
		buf       []byte
	}
	partials := make(map[uint32]*partial)
	order := make([]uint32, 0, len(msgs))
	var generation uint32

	for _, msg := range msgs {
		ad, err := netlink.NewAttributeDecoder(msg.Data)
		if err != nil {
			return nil, fmt.Errorf("creating attribute decoder: %w", err)
		}

		var evType, msgLen, msgGen uint32
		var chunk []byte
		var hasType, hasLen, hasVal, hasGen bool

		for ad.Next() {
			switch ad.Type() {
			case attrType:
				evType = ad.Uint32()
				hasType = true
			case attrGeneration:
				msgGen = ad.Uint32()
				hasGen = true
			case attrLength:
				msgLen = ad.Uint32()
				hasLen = true
			case attrVal:
				chunk = ad.Bytes()
				hasVal = true
			}
		}
		if err := ad.Err(); err != nil {
			return nil, fmt.Errorf("decoding netlink reply attributes: %w", err)
		}
		if !hasType {
			continue
		}
		if hasGen && generation == 0 {
			generation = msgGen
		}

		p := partials[evType]
		if p == nil {
			p = &partial{}
			partials[evType] = p
			order = append(order, evType)
		}
		if hasLen && !p.hasLength {
			p.length = msgLen
			p.hasLength = true
		}
		if hasVal {
			p.buf = append(p.buf, chunk...)
		}
	}

	objects := make([]EvidenceObject, 0, len(order))
	for _, evType := range order {
		p := partials[evType]
		if p.hasLength && uint32(len(p.buf)) != p.length {
			return nil, fmt.Errorf("device-evidence object type %d: reassembled %d bytes, expected %d",
				evType, len(p.buf), p.length)
		}
		objects = append(objects, EvidenceObject{Type: evType, Val: p.buf})
	}

	return &ReadResult{Objects: objects, Generation: generation}, nil
}
