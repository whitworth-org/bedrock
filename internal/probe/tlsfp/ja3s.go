package tlsfp

import (
	"crypto/md5" //nolint:gosec // JA3S is defined as md5 by Salesforce 2017; not a security primitive here
	"encoding/hex"
	"strconv"
	"strings"
)

// computeJA3S returns the JA3S md5 hex digest and the underlying CSV string
// the digest was computed over.
//
// Format (Salesforce, 2017):
//
//	JA3S = md5("<TLSVersion>,<Cipher>,<Ext1>-<Ext2>-...")
//
// Values are decimal, not hex. TLSVersion is the wire `legacy_version` from
// the ServerHello — for TLS 1.3 connections this is 0x0303 (771), since
// TLS 1.3 freezes the legacy_version field and signals 1.3 via the
// supported_versions extension. This matches Salesforce's reference.
//
// Extensions are listed in the order the server emitted them. The hash is
// MD5 not because MD5 is secure but because the original spec defined it
// that way — collisions don't matter for a non-cryptographic identifier.
func computeJA3S(wireVersion, cipher uint16, exts []uint16) (string, string) {
	parts := make([]string, len(exts))
	for i, e := range exts {
		parts[i] = strconv.Itoa(int(e))
	}
	raw := strconv.Itoa(int(wireVersion)) + "," +
		strconv.Itoa(int(cipher)) + "," +
		strings.Join(parts, "-")
	sum := md5.Sum([]byte(raw)) //nolint:gosec // see comment above
	return hex.EncodeToString(sum[:]), raw
}
