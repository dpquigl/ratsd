// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package tdispclaims implements a RATSd evidence attester plugin for
// host-observed TDISP interface state (TDM_System_Architecture.md §4.4.2).
//
// The DAT/UCS SPDM claims produced by the sibling deviceevidence plugin
// (§8.1/§8.5) can only restate what the device's own SPDM Responder observed
// about itself; TDISP interface acceptance also depends on host-side facts —
// notably the GET_DEVICE_INTERFACE_REPORT payload the host kernel/TDX module
// collected during LOCK_INTERFACE — that the device cannot attest to.
//
// This plugin reads only the "report" evidence object from the same
// device-evidence generic netlink family deviceevidence uses (via
// deviceevidence.ReadEvidence), plus the device's certificate chain for
// identity cross-check, and returns them as an spdm-claims claims-map (§8.4)
// using the certificates+device-interface-report alternative (§8.6). Unlike
// deviceevidence, this plugin only ever produces this one shape, so it
// returns the claims-map bytes directly as evidence — no self-describing
// envelope is needed.
//
// The plugin is selected by TDM via the attester-selection key "tdisp-claims"
// and requires the option "pci-bdf" (the PCI Bus:Device.Function address of
// the target TDI device, e.g. "0000:01:00.0").
package tdispclaims

import (
	"encoding/json"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/veraison/ratsd/attesters/deviceevidence"
	"github.com/veraison/ratsd/proto/compositor"
)

const (
	// PluginName is the attester-selection key used by TDM.
	PluginName    = "tdisp-claims"
	pluginVersion = "0.1.0"

	// nonceMaxSize matches the kernel ABI limit (max-nonce-size in
	// device-evidence.yaml), same as deviceevidence.
	nonceMaxSize = 32
)

var (
	sid = &compositor.SubAttesterID{
		Name:    PluginName,
		Version: pluginVersion,
	}

	// This plugin only ever produces one shape (§8.6), so — unlike
	// deviceevidence — it can declare its real content type up front instead
	// of routing through a self-describing envelope.
	supportedFormats = []*compositor.Format{
		{
			ContentType: deviceevidence.FormatEATUCSCBOR,
			NonceSize:   nonceMaxSize,
		},
	}

	statusOK = &compositor.Status{Result: true, Error: ""}
)

// Plugin implements the RATSd IPluggable interface for tdisp-claims.
type Plugin struct{}

func errOut(e error) *compositor.EvidenceOut {
	return &compositor.EvidenceOut{
		Status: &compositor.Status{Result: false, Error: e.Error()},
	}
}

func (p *Plugin) GetSubAttesterID() *compositor.SubAttesterIDOut {
	return &compositor.SubAttesterIDOut{SubAttesterID: sid, Status: statusOK}
}

// GetSupportedFormats probes for the device-evidence netlink family. If the
// kernel module is not loaded the plugin reports itself as unavailable so
// RATSd can skip it rather than returning an error at evidence-collection
// time.
func (p *Plugin) GetSupportedFormats() *compositor.SupportedFormatsOut {
	if err := deviceevidence.FamilyAvailable(); err != nil {
		return &compositor.SupportedFormatsOut{
			Status: &compositor.Status{
				Result: false,
				Error:  fmt.Sprintf("device-evidence kernel family not available: %v", err),
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

	if in.ContentType != deviceevidence.FormatEATUCSCBOR {
		return errOut(fmt.Errorf("unsupported content type %q; expected %q",
			in.ContentType, deviceevidence.FormatEATUCSCBOR))
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

	result, err := deviceevidence.ReadEvidence(bdf, in.Nonce)
	if err != nil {
		return errOut(fmt.Errorf("reading device-evidence for %s: %w", bdf, err))
	}

	report, ok := result.Object(deviceevidence.EvTypeReport)
	if !ok {
		return errOut(fmt.Errorf("no TDISP interface report available for %s", bdf))
	}

	certs := make(map[uint8][]byte)
	for slot, t := range deviceevidence.EvTypeCerts {
		if c, ok := result.Object(t); ok {
			certs[uint8(slot)] = c
		}
	}

	claims := deviceevidence.SPDMClaims{
		EATProfile:   deviceevidence.EATProfileSPDM,
		Certificates: certs,
		DeviceInterfaceReport: &deviceevidence.TDISPDeviceInterfaceReport{
			DeviceSpecificInfo: report,
		},
	}

	encoded, err := cbor.Marshal(claims)
	if err != nil {
		return errOut(fmt.Errorf("encoding spdm-claims: %w", err))
	}

	return &compositor.EvidenceOut{Status: statusOK, Evidence: encoded}
}

// GetPlugin returns a ready-to-serve Plugin instance, matching the
// GetPlugin()-factory convention used by sibling plugins (e.g. mocktsm).
func GetPlugin() *Plugin {
	return &Plugin{}
}
