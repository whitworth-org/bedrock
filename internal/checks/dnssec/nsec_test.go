package dnssec

import (
	"context"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/report"
)

// TestRunNSECProbeFailure pins that a resolver failing the NSEC probe makes
// the result inconclusive instead of reporting a missing NSEC record.
func TestRunNSECProbeFailure(t *testing.T) {
	z := newSignedZone(t)
	zone := &zoneResolver{rrs: z.healthy(),
		rcode: map[uint16]int{mdns.TypeA: mdns.RcodeServerFailure}}

	res := runNSEC(context.Background(), serveZone(t, zone, 2*time.Second))

	checkResults(t, res, map[string]want{"dnssec.nsec.type": {report.Warn,
		"NSEC/NSEC3 probe failed", "resolver answered SERVFAIL"}})
}
