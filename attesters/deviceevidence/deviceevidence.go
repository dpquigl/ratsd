// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package deviceevidence implements a RATSd evidence attester plugin for the
// device-evidence generic netlink interface exposed by the devsec/tsm Linux
// kernel branch (devsec-phase2).
//
// It collects SPDM certificate chains (cert0–cert7), VCA transcript,
// measurement response, and TDISP interface report from the guest kernel's
// device-evidence interface, reassembling any object split across multiple
// netlink messages. It then locates measurement index 0xFD and dispatches on
// its DMTF measurement type:
//
//   - If 0xFD is a structured measurement manifest (type 0x0A, masked), the
//     plugin treats the value as an SVH-prefixed EAT Device Assignment Token
//     (a self-signed COSE_Sign1), strips the SVH, and forwards the manifest
//     bytes verbatim (application/eat+cwt) — purely mechanical, no re-encoding.
//   - Otherwise (0xFD absent, or a different measurement type), the plugin
//     builds the same spdm-claims shape (TDX-Connect-Verifier spec §8.4) that
//     a device-signed DAT would carry, directly from the raw SPDM session
//     objects, and returns it as a plain unsigned CBOR value (§8.5,
//     application/eat-ucs+cbor).
//
// Either way, the result is wrapped in a single self-describing CBOR envelope
// (EvidenceBundle) whose outer declared content-type is always
// FormatRawObjects; the inner "format" field carries which of the two above
// actually varies at runtime. (This indirection is a workaround for
// compositor.EvidenceOut having no content-type field of its own — see the
// package-level comment on FormatRawObjects.)
//
// The plugin is selected by TDM via the attester-selection key "device-evidence"
// and requires the option "pci-bdf" (the PCI Bus:Device.Function address of the
// target TDI device, e.g. "0000:01:00.0").
package deviceevidence

import (
	"encoding/json"
	"fmt"
	"log"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/veraison/ratsd/proto/compositor"
)

const (
	// PluginName is the attester-selection key used by TDM.
	PluginName    = "device-evidence"
	pluginVersion = "0.1.0"

	// FormatEATCWT is the inner evidence format for an EAT Device Assignment
	// Token (a COSE_Sign1-wrapped CWT), forwarded verbatim from measurement
	// index 0xFD.
	FormatEATCWT = "application/eat+cwt"

	// EATProfileSPDM is the eat_profile claim value (spec §8.4/§8.5/§8.6) for
	// the spdm-claims shape, shared by the DAT, the RATSd-crafted SPDM
	// fallback, and the tdisp-claims record.
	EATProfileSPDM = "tag:linaro.org,2025:device-spdm#1.0.0"

	// FormatEATUCSCBOR is the inner evidence format for the RATSd-crafted
	// spdm-claims fallback bundle (spec §8.5): a plain, unsigned CBOR value
	// carrying the same claims-set shape a device-signed DAT would, trusted
	// only via the enclosing ratsd-token's signature.
	FormatEATUCSCBOR = `application/eat-ucs+cbor; eat_profile="` + EATProfileSPDM + `"`

	// FormatRawObjects is the outer envelope content-type declared to RATSd
	// core/the CMW layer. It never changes at runtime: the envelope's inner
	// "format" field (FormatEATCWT or FormatEATUCSCBOR) is what varies.
	//
	// This is a workaround for compositor.EvidenceOut carrying no
	// content-type field: RATSd core's CMW assembly (api/server.go) tags a
	// plugin's record with whatever GetSupportedFormats() returned before
	// GetEvidence() runs, so it can't reflect this plugin's runtime
	// DAT-vs-UCS choice. A consumer must unwrap EvidenceBundle.Format to
	// learn the real content-type; api/server.go does not do this today.
	FormatRawObjects = "application/vnd.veraison.device-evidence+cbor"

	// datMeasurementType is the DMTF StructuredMeasurementManifest type
	// (masked; see measType) used by measurement index 0xFD to signal an EAT
	// Device Assignment Token.
	datMeasurementType uint8 = 0x0A

	// datIndex and deviceModeIndex are the two SPDM-reserved measurement
	// block indices (SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST
	// / _DEVICE_MODE in libspdm), excluded from spdm-measurements by §8.4's
	// CDDL (block-id = 1..239).
	datIndex        uint8 = 0xFD
	deviceModeIndex uint8 = 0xFE

	// nonceMaxSize matches the kernel ABI limit (max-nonce-size in
	// device-evidence.yaml).
	nonceMaxSize = 32
)

var (
	sid = &compositor.SubAttesterID{
		Name:    PluginName,
		Version: pluginVersion,
	}

	supportedFormats = []*compositor.Format{
		{
			ContentType: FormatRawObjects,
			NonceSize:   32,
		},
	}

	statusOK = &compositor.Status{Result: true, Error: ""}
)

// Plugin implements the RATSd IPluggable interface for device-evidence.
type Plugin struct{}

func errOut(e error) *compositor.EvidenceOut {
	return &compositor.EvidenceOut{
		Status: &compositor.Status{Result: false, Error: e.Error()},
	}
}

func (p *Plugin) GetSubAttesterID() *compositor.SubAttesterIDOut {
	return &compositor.SubAttesterIDOut{SubAttesterID: sid, Status: statusOK}
}

// GetSupportedFormats probes for the device-evidence netlink family. If the kernel
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

	if in.ContentType != FormatRawObjects {
		return errOut(fmt.Errorf("unsupported content type %q; expected %q",
			in.ContentType, FormatRawObjects))
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

	result, err := ReadEvidence(bdf, in.Nonce)
	if err != nil {
		return errOut(fmt.Errorf("reading device-evidence for %s: %w", bdf, err))
	}
	if len(result.Objects) == 0 {
		return errOut(fmt.Errorf("no evidence objects returned for %s", bdf))
	}

	format, evidence, err := buildEvidence(bdf, result)
	if err != nil {
		return errOut(fmt.Errorf("building evidence for %s: %w", bdf, err))
	}

	encoded, err := cbor.Marshal(EvidenceBundle{
		DevName:    bdf,
		Nonce:      in.Nonce,
		Generation: result.Generation,
		Format:     format,
		Evidence:   evidence,
	})
	if err != nil {
		return errOut(fmt.Errorf("encoding evidence envelope: %w", err))
	}

	return &compositor.EvidenceOut{Status: statusOK, Evidence: encoded}
}

// buildEvidence implements the DAT-vs-spdm-claims-fallback dispatch: locate
// the measurements object, look for index 0xFD, and either forward the DAT
// manifest verbatim or fall back to assembling an spdm-claims bundle.
//
// A measurements object that exists but fails to parse as a well-formed
// GET_MEASUREMENTS response is a hard failure (corrupt evidence), not a
// trigger for the fallback path.
func buildEvidence(bdf string, result *ReadResult) (format string, evidence []byte, err error) {
	meas, ok := result.Object(EvTypeMeasurements)
	if !ok {
		sc, err := buildSPDMClaimsFallback(result, nil)
		if err != nil {
			return "", nil, err
		}
		return FormatEATUCSCBOR, sc, nil
	}

	mr, err := parseMeasurementsResponse(meas)
	if err != nil {
		return "", nil, fmt.Errorf("parsing measurements object: %w", err)
	}

	if blk, found := findBlock(mr.Blocks, datIndex); found && measType(blk.DMTFType) == datMeasurementType {
		manifest, err := buildDAT(blk)
		if err != nil {
			return "", nil, fmt.Errorf("building DAT from measurement index 0x%02x: %w", datIndex, err)
		}
		if manifest != nil {
			return FormatEATCWT, manifest, nil
		}
		log.Printf("device-evidence: measurement index 0x%02x for %s claims a structured manifest but is not a recognized DAT SVH; falling back to spdm-claims", datIndex, bdf)
	}

	sc, err := buildSPDMClaimsFallback(result, mr)
	if err != nil {
		return "", nil, err
	}
	return FormatEATUCSCBOR, sc, nil
}

// buildDAT strips the SVH from a structured-measurement-manifest block and
// validates that what remains is a well-formed COSE_Sign1 manifest.
//
// It returns (nil, nil) — not an error — if the SVH names a registry/vendor
// other than IANA-CBOR (0x0A) tagged with COSE_Sign1 (0xD2): that means index
// 0xFD isn't actually carrying a DAT despite having the structured-manifest
// measurement type, so the caller should fall back to Concise Evidence.
// A non-nil error means the SVH/manifest is malformed, which — since the type
// byte already promised a DAT — is treated as corrupt evidence.
func buildDAT(blk *measurementBlock) ([]byte, error) {
	id, vendorID, manifest, err := parseSVH(blk.Value)
	if err != nil {
		return nil, fmt.Errorf("parsing SVH: %w", err)
	}
	if id != svhIDIANACBOR || len(vendorID) != 1 || vendorID[0] != cborTagCOSESign1 {
		return nil, nil
	}
	if err := validateCOSESign1(manifest); err != nil {
		return nil, fmt.Errorf("validating COSE_Sign1 manifest: %w", err)
	}
	return manifest, nil
}

// EvidenceBundle is the top-level CBOR envelope returned to RATSd core and
// ultimately forwarded (as the "device-evidence" CMW monad's value) to TDM.
// Its outer content-type is always FormatRawObjects; Format carries which
// inner encoding Evidence actually uses.
type EvidenceBundle struct {
	DevName    string `cbor:"dev-name"`
	Nonce      []byte `cbor:"nonce"`
	Generation uint32 `cbor:"generation"`
	Format     string `cbor:"format"` // FormatEATCWT or FormatEATUCSCBOR
	Evidence   []byte `cbor:"evidence"`
}

// SPDMClaims is the spdm-claims shape shared by all three carriage modes in
// TDM_System_Architecture.md §8.4: a device-signed DAT (§8.1), the
// RATSd-crafted SPDM fallback built here (§8.5), and the tdisp-claims record
// (§8.6, built by the sibling tdispclaims package). Field labels are the
// integer claim labels from §8.4's CDDL (eat_profile/measurements/
// certificates/vca/device-interface-report); see MeasurementClaim and
// TDISPDeviceInterfaceReport for the nested shapes.
//
// Exported for reuse by the tdispclaims plugin, which populates
// Certificates and DeviceInterfaceReport but not Measurements/VCA.
type SPDMClaims struct {
	EATProfile            string                      `cbor:"265,keyasint"`
	Measurements          map[uint8]MeasurementClaim   `cbor:"3802,keyasint,omitempty"`
	Certificates          map[uint8][]byte             `cbor:"3803,keyasint"`
	VCA                   []byte                       `cbor:"3804,keyasint,omitempty"`
	DeviceInterfaceReport *TDISPDeviceInterfaceReport   `cbor:"3808,keyasint,omitempty"`
}

// MeasurementClaim is a single spdm-measurement entry (§8.4), keyed in
// SPDMClaims.Measurements by SPDM Measurement Block index. Exactly one of
// DigestMeasurement or RawMeasurement is populated, mirroring the DMTF
// measurement value's format bit (measFormat): Digest (0) or Bitstream (1).
type MeasurementClaim struct {
	ComponentType     uint8              `cbor:"1,keyasint"`
	DigestMeasurement *DigestMeasurement `cbor:"2,keyasint,omitempty"`
	RawMeasurement    []byte             `cbor:"3,keyasint,omitempty"`
}

// DigestMeasurement is the [alg, val] array form of a digest-measurement
// claim (§8.4: "an ARRAY, not a bare bstr").
type DigestMeasurement struct {
	_   struct{} `cbor:",toarray"`
	Alg string
	Val []byte
}

// digestAlg is the hardcoded digest algorithm identifier used for every
// digest-measurement claim this plugin builds. No SPDM algorithm-negotiation
// data reaches this layer, so this matches the value the spec's own
// generated sample (manifest-exi.diag) uses.
const digestAlg = "sha-384"

// TDISPDeviceInterfaceReport is the tdisp-device-interface-report claim
// (§8.4). This PoC (and the tdispclaims plugin) only ever populates
// device-specific-info (claim 6) with the raw, undecomposed
// GET_DEVICE_INTERFACE_REPORT payload; the other fields require kernel UAPI
// this PoC does not have (§4.4.2), so they are omitted from this type rather
// than modeled as always-absent optional fields.
type TDISPDeviceInterfaceReport struct {
	DeviceSpecificInfo []byte `cbor:"6,keyasint"`
}

// buildSPDMClaimsFallback assembles and CBOR-encodes the spdm-claims fallback
// bundle (spec §8.5) from whatever objects the netlink read produced, plus
// (if available) the already-parsed measurements response. mr may be nil if
// no measurements object was returned at all, in which case Measurements is
// left empty.
func buildSPDMClaimsFallback(result *ReadResult, mr *measurementsResponse) ([]byte, error) {
	vca, ok := result.Object(EvTypeVCA)
	if !ok {
		log.Printf("device-evidence: no VCA object; the kernel may have folded it into the measurements transcript instead")
	}

	certs := make(map[uint8][]byte)
	for slot, t := range EvTypeCerts {
		if c, ok := result.Object(t); ok {
			certs[uint8(slot)] = c
		}
	}

	var measurements map[uint8]MeasurementClaim
	if mr != nil {
		measurements = make(map[uint8]MeasurementClaim, len(mr.Blocks))
		for _, blk := range mr.Blocks {
			// block-id excludes 0xFD (the DAT/manifest index itself) and
			// 0xFE (SPDM's reserved device-mode index) — §8.4 CDDL.
			if blk.Index == datIndex || blk.Index == deviceModeIndex {
				continue
			}
			claim := MeasurementClaim{ComponentType: measType(blk.DMTFType)}
			if measFormat(blk.DMTFType) == 0 {
				claim.DigestMeasurement = &DigestMeasurement{Alg: digestAlg, Val: blk.Value}
			} else {
				claim.RawMeasurement = blk.Value
			}
			measurements[blk.Index] = claim
		}
	}

	return cbor.Marshal(SPDMClaims{
		EATProfile:   EATProfileSPDM,
		Measurements: measurements,
		Certificates: certs,
		VCA:          vca,
	})
}
