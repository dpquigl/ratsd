// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package pcitsm implements a RATSd evidence attester plugin for the pci-tsm
// generic netlink interface exposed by the devsec/tsm Linux kernel branch.
//
// It collects SPDM certificate chains (cert0–cert7), VCA transcript,
// measurement response, and TDISP interface report from the guest kernel's
// pci-tsm driver and returns them as a CBOR-encoded evidence bundle.
//
// The plugin is selected by TDM via the attester-selection key "pci-tsm" and
// requires the option "pci-bdf" (the PCI Bus:Device.Function address of the
// target TDI device, e.g. "0000:01:00.0").
package pcitsm

import (
	"encoding/json"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/veraison/ratsd/proto/compositor"
)

const (
	// PluginName is the attester-selection key used by TDM.
	PluginName = "pci-tsm"
	pluginVersion = "0.1.0"

	// ContentType is the MIME type for the CBOR-encoded pci-tsm evidence bundle.
	ContentType = "application/vnd.veraison.pci-tsm+cbor"

	// nonceMaxSize matches the kernel ABI limit (max-nonce-size in pci-tsm.yaml).
	nonceMaxSize = 256
)

var (
	sid = &compositor.SubAttesterID{
		Name:    PluginName,
		Version: pluginVersion,
	}

	supportedFormats = []*compositor.Format{
		{
			ContentType: ContentType,
			NonceSize:   32,
		},
	}

	statusOK = &compositor.Status{Result: true, Error: ""}
)

// Plugin implements the RATSd IPluggable interface for pci-tsm evidence.
type Plugin struct{}

func errOut(e error) *compositor.EvidenceOut {
	return &compositor.EvidenceOut{
		Status: &compositor.Status{Result: false, Error: e.Error()},
	}
}

func (p *Plugin) GetSubAttesterID() *compositor.SubAttesterIDOut {
	return &compositor.SubAttesterIDOut{SubAttesterID: sid, Status: statusOK}
}

// GetSupportedFormats probes for the pci-tsm netlink family. If the kernel
// module is not loaded the plugin reports itself as unavailable so RATSd can
// skip it rather than returning an error at evidence-collection time.
func (p *Plugin) GetSupportedFormats() *compositor.SupportedFormatsOut {
	conn, err := genetlinkDial()
	if err == nil {
		_, err = conn.GetFamily(familyName)
		conn.Close()
	}
	if err != nil {
		return &compositor.SupportedFormatsOut{
			Status: &compositor.Status{
				Result: false,
				Error:  fmt.Sprintf("pci-tsm kernel family not available: %v", err),
			},
		}
	}
	return &compositor.SupportedFormatsOut{Status: statusOK, Formats: supportedFormats}
}

func (p *Plugin) GetOptions() *compositor.OptionsOut {
	return &compositor.OptionsOut{
		Status: statusOK,
		Options: []*compositor.Option{
			{Name: "pci-bdf", Type: "string"},
		},
	}
}

func (p *Plugin) GetEvidence(in *compositor.EvidenceIn) *compositor.EvidenceOut {
	if len(in.Nonce) == 0 || len(in.Nonce) > nonceMaxSize {
		return errOut(fmt.Errorf("nonce must be 1–%d bytes, got %d",
			nonceMaxSize, len(in.Nonce)))
	}

	if in.ContentType != ContentType {
		return errOut(fmt.Errorf("unsupported content type %q; expected %q",
			in.ContentType, ContentType))
	}

	var opts map[string]string
	if len(in.Options) > 0 {
		if err := json.Unmarshal(in.Options, &opts); err != nil {
			return errOut(fmt.Errorf("parsing options: %w", err))
		}
	}

	bdf, ok := opts["pci-bdf"]
	if !ok || bdf == "" {
		return errOut(fmt.Errorf("required option \"pci-bdf\" not provided"))
	}

	objects, err := readEvidence(bdf, in.Nonce)
	if err != nil {
		return errOut(fmt.Errorf("reading pci-tsm evidence for %s: %w", bdf, err))
	}
	if len(objects) == 0 {
		return errOut(fmt.Errorf("no evidence objects returned for %s", bdf))
	}

	encoded, err := encodeBundle(bdf, in.Nonce, objects)
	if err != nil {
		return errOut(fmt.Errorf("encoding evidence bundle: %w", err))
	}

	return &compositor.EvidenceOut{Status: statusOK, Evidence: encoded}
}

// EvidenceBundle is the top-level CBOR structure returned to RATSd and
// ultimately forwarded to the Veraison verifier.
type EvidenceBundle struct {
	DevName string           `cbor:"dev-name"`
	Nonce   []byte           `cbor:"nonce"`
	Objects []evidenceObject `cbor:"objects"`
}

type evidenceObject struct {
	Type uint32 `cbor:"type"`
	Val  []byte `cbor:"val"`
}

func encodeBundle(bdf string, nonce []byte, raw []EvidenceObject) ([]byte, error) {
	objs := make([]evidenceObject, len(raw))
	for i, o := range raw {
		objs[i] = evidenceObject{Type: o.Type, Val: o.Val}
	}
	return cbor.Marshal(EvidenceBundle{DevName: bdf, Nonce: nonce, Objects: objs})
}
