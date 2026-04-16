// Package bimi implements BIMI checks aligned with Gmail's vendor
// requirements. There is no IETF RFC for BIMI; the spec is the BIMI Group
// draft (https://bimigroup.org/) and Gmail's BIMI configuration guide.
//
// Check ordering matters within the package: the TXT check populates the
// shared cache that the SVG and VMC checks consume. Categories run in
// parallel but checks within a category run sequentially (see registry.Run),
// so the BIMI checks see each other's cached output.
package bimi

import "granite-scan/internal/registry"

const category = "BIMI"

func init() {
	registry.Register(recordCheck{})
	registry.Register(svgFetchCheck{})
	registry.Register(svgProfileCheck{})
	registry.Register(svgAspectCheck{})
	registry.Register(vmcFetchCheck{})
	registry.Register(vmcChainCheck{})
	registry.Register(vmcLogotypeCheck{})
	registry.Register(gmailGateCheck{})
}
