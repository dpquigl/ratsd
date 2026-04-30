// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package pcitsm

import (
	"fmt"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

const (
	familyName    = "pci-tsm"
	familyVersion = 1

	// Commands (pci-tsm-netlink.h: PCI_TSM_CMD_EVIDENCE_READ)
	cmdEvidenceRead uint8 = 1

	// Attribute IDs for the evidence-object attribute set (pci-tsm-netlink.h)
	attrType     uint16 = 1
	attrTypeMask uint16 = 2
	// attrFlags uint16 = 3  (unused in requests for now)
	attrDevName uint16 = 4
	attrNonce   uint16 = 5
	attrVal     uint16 = 6

	// evidenceTypeFlagAll requests cert0–cert7, vca, measurements, and report
	// (11 evidence types, one bit per type).
	evidenceTypeFlagAll uint32 = 0x7FF
)

// EvidenceObject is a single evidence object returned by the kernel.
type EvidenceObject struct {
	Type uint32
	Val  []byte
}

// genetlinkDial is a thin wrapper so pcitsm.go can probe availability
// without importing the genetlink package directly.
func genetlinkDial() (*genetlink.Conn, error) {
	return genetlink.Dial(nil)
}

// readEvidence opens a generic netlink socket, resolves the pci-tsm family,
// and issues an evidence-read dump request for the device identified by bdf
// with the given nonce. It returns all evidence objects streamed back by the
// kernel.
//
// Requires CAP_NET_ADMIN. Blocks the calling goroutine; call via
// goroutine or spawn_blocking equivalent when used from async contexts.
func readEvidence(bdf string, nonce []byte) ([]EvidenceObject, error) {
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

	// Build request attributes: type-mask, dev-name (null-terminated), nonce.
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(attrTypeMask, evidenceTypeFlagAll)
	ae.Bytes(attrDevName, []byte(bdf+"\x00"))
	ae.Bytes(attrNonce, nonce)

	attrData, err := ae.Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding netlink request attributes: %w", err)
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: cmdEvidenceRead,
			Version: familyVersion,
		},
		Data: attrData,
	}

	msgs, err := conn.Execute(req, family.ID, netlink.Request|netlink.Dump)
	if err != nil {
		return nil, fmt.Errorf("executing evidence-read dump: %w", err)
	}

	objects := make([]EvidenceObject, 0, len(msgs))
	for _, msg := range msgs {
		ad, err := netlink.NewAttributeDecoder(msg.Data)
		if err != nil {
			return nil, fmt.Errorf("creating attribute decoder: %w", err)
		}

		var obj EvidenceObject
		var hasType, hasVal bool

		for ad.Next() {
			switch ad.Type() {
			case attrType:
				obj.Type = ad.Uint32()
				hasType = true
			case attrVal:
				obj.Val = ad.Bytes()
				hasVal = true
			}
		}
		if err := ad.Err(); err != nil {
			return nil, fmt.Errorf("decoding netlink reply attributes: %w", err)
		}

		if hasType && hasVal {
			objects = append(objects, obj)
		}
	}

	return objects, nil
}
