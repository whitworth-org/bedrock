package bimi

// RFC 3709 LogotypeExtn ASN.1 decoder.
//
// The BIMI Group profile of the Verified Mark Certificate (VMC) reuses RFC
// 3709's LogotypeExtension (OID 1.3.6.1.5.5.7.1.12) to bind the served SVG
// logo bytes to the certificate via a SHA-256 hash. Earlier revisions of
// this code performed a raw byte-search for the SVG digest inside the
// extension value — that worked in practice but did not actually validate
// the structure. This file implements a proper ASN.1 walk so the VMC
// logotype check can:
//
//   1. enumerate every embedded image entry (LogotypeImage),
//   2. surface the declared media type and URI as evidence, and
//   3. compare the publisher's SVG digest against the hashes the CA signed,
//      not just any byte sequence that happens to contain the digest.
//
// Only the subjectLogo path is decoded (BIMI never populates community,
// issuer, or other-logo entries) — but the surrounding optional fields are
// skipped tolerantly so we don't fail certs that include them.

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// LogotypeImage is the flattened view of a single LogotypeImage entry that
// the VMC logotype check actually consumes. We expose the algorithm OID and
// raw hash bytes so the caller can verify against any algorithm BIMI may
// adopt in the future (today: SHA-256, OID 2.16.840.1.101.3.4.2.1).
type LogotypeImage struct {
	MediaType string
	HashAlg   asn1.ObjectIdentifier
	HashValue []byte
	URI       string
}

// ---------------------------------------------------------------------------
// ASN.1 mirror types. Field names and tags are chosen to match RFC 3709 §4.1.
//
// Notes on encoding/asn1 quirks that affect this layout:
//   - CHOICE is not natively supported. The two LogotypeInfo arms (direct vs.
//     indirect) are decoded by trying the direct arm first and discarding
//     trailing parse errors. BIMI VMCs always use the direct arm.
//   - Each "[N] EXPLICIT" wrapper requires `tag:N,explicit,optional` in the
//     struct tag so the asn1 package emits the matching context-specific
//     header.
// ---------------------------------------------------------------------------

// hashAlgAndValue mirrors the RFC 3709 HashAlgAndValue SEQUENCE.
type hashAlgAndValue struct {
	HashAlg   pkix.AlgorithmIdentifier
	HashValue []byte
}

// logotypeDetails mirrors RFC 3709 LogotypeDetails.
//
// LogotypeURI is `SEQUENCE OF IA5String`. encoding/asn1 cannot express
// element-level tags on a slice (an `ia5` tag on `[]string` is applied to
// the SEQUENCE wrapper, not each element, and triggers a marshal error),
// so we capture the SEQUENCE as a raw value and decode the IA5String
// elements manually in extractIA5StringSeq.
type logotypeDetails struct {
	MediaType    string `asn1:"ia5"`
	LogotypeHash []hashAlgAndValue
	LogotypeURI  asn1.RawValue
}

// logotypeImageInfo mirrors RFC 3709 LogotypeImageInfo. Decoded only enough
// to consume the bytes off the stream so subsequent SEQUENCE entries align;
// none of its fields are exposed today.
type logotypeImageInfo struct {
	Raw asn1.RawContent
}

// logotypeImage mirrors RFC 3709 LogotypeImage.
type logotypeImage struct {
	ImageDetails logotypeDetails
	ImageInfo    logotypeImageInfo `asn1:"optional"`
}

// logotypeAudio is parsed only enough to skip past it.
type logotypeAudio struct {
	Raw asn1.RawContent
}

// logotypeData mirrors RFC 3709 LogotypeData.
//
// Per the RFC, both fields are OPTIONAL but at least one must appear. The
// `image` field has IMPLICIT tag 0 in some interpretations and is untagged
// in the canonical text — we treat it as untagged SEQUENCE OF, which is
// what every BIMI-issuing CA currently emits.
type logotypeData struct {
	Image []logotypeImage `asn1:"optional"`
	Audio []logotypeAudio `asn1:"tag:1,optional"`
}

// logotypeInfoDirect wraps the direct arm of the LogotypeInfo CHOICE.
// LogotypeInfo direct is `[0] LogotypeData` (context-specific, IMPLICIT in
// effect because LogotypeData is itself a SEQUENCE — the `tag:0` form below
// reads it back).
type logotypeInfoDirect struct {
	Data logotypeData `asn1:"tag:0"`
}

// logotypeExtn mirrors RFC 3709 LogotypeExtn. Only subjectLogo is meaningful
// for BIMI; the other three fields are decoded as opaque content so a CA
// that includes (e.g.) communityLogos doesn't break the parse.
type logotypeExtn struct {
	CommunityLogos asn1.RawValue      `asn1:"tag:0,explicit,optional"`
	IssuerLogo     asn1.RawValue      `asn1:"tag:1,explicit,optional"`
	SubjectLogo    logotypeInfoDirect `asn1:"tag:2,explicit,optional"`
	OtherLogos     asn1.RawValue      `asn1:"tag:3,explicit,optional"`
}

// DecodeLogotypeExtn parses a raw RFC 3709 LogotypeExtn extension value
// (the bytes of the X.509 extension whose OID is 1.3.6.1.5.5.7.1.12) and
// returns one entry per LogotypeImage in the subject logo's direct
// LogotypeData. It returns an error when the extension cannot be parsed at
// all, when the indirect form is used (BIMI requires direct), or when no
// images are present.
func DecodeLogotypeExtn(raw []byte) ([]LogotypeImage, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty logotype extension")
	}

	var ext logotypeExtn
	rest, err := asn1.Unmarshal(raw, &ext)
	if err != nil {
		// Some CAs wrap the extension in a single-element SEQUENCE with the
		// subjectLogo tag missing; fall back to trying logotypeInfoDirect at
		// the top level so we still recognize those.
		var alt logotypeInfoDirect
		if _, fbErr := asn1.UnmarshalWithParams(raw, &alt, "tag:2,explicit"); fbErr == nil {
			return imagesFrom(alt.Data)
		}
		return nil, fmt.Errorf("parse LogotypeExtn: %w", err)
	}
	// Trailing bytes are tolerated by the spec but unusual; surface them only
	// if absolutely nothing parsed.
	_ = rest

	// SubjectLogo is the only field BIMI uses. If it's absent, signal that
	// explicitly so the caller can produce a clear FAIL evidence string.
	images, err := imagesFrom(ext.SubjectLogo.Data)
	if err != nil {
		return nil, err
	}
	return images, nil
}

// imagesFrom flattens a LogotypeData into the public LogotypeImage view.
func imagesFrom(d logotypeData) ([]LogotypeImage, error) {
	if len(d.Image) == 0 {
		return nil, errors.New("LogotypeData carries no image entries")
	}
	out := make([]LogotypeImage, 0, len(d.Image))
	for _, img := range d.Image {
		// LogotypeURI is SIZE(1..MAX); pick the first as evidence. Same for
		// LogotypeHash — the hash list is per-image and the BIMI guidance is
		// to publish a single SHA-256 entry, but we expose just the first
		// (callers iterate the returned slice if they want to test multiples).
		uris, err := extractIA5StringSeq(img.ImageDetails.LogotypeURI)
		if err != nil {
			return nil, fmt.Errorf("decode LogotypeURI: %w", err)
		}
		var uri string
		if len(uris) > 0 {
			uri = uris[0]
		}
		if len(img.ImageDetails.LogotypeHash) == 0 {
			return nil, errors.New("LogotypeDetails missing logotypeHash entries")
		}
		// Emit one LogotypeImage per (image, hash) pair so a caller can match
		// the publisher's SVG digest against any of the hashes the CA bound.
		for _, h := range img.ImageDetails.LogotypeHash {
			out = append(out, LogotypeImage{
				MediaType: img.ImageDetails.MediaType,
				HashAlg:   h.HashAlg.Algorithm,
				HashValue: append([]byte(nil), h.HashValue...),
				URI:       uri,
			})
		}
	}
	return out, nil
}

// encodeIA5StringSeq is the inverse of extractIA5StringSeq. Used by the
// tests to construct synthetic LogotypeExtn DER blobs; not used in the
// production decode path.
func encodeIA5StringSeq(values []string) (asn1.RawValue, error) {
	var body []byte
	for _, v := range values {
		// Wrap each string as a primitive IA5String (universal class, tag 22).
		one, err := asn1.MarshalWithParams(v, "ia5")
		if err != nil {
			return asn1.RawValue{}, err
		}
		body = append(body, one...)
	}
	rv := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      body,
	}
	full, err := asn1.Marshal(rv)
	if err != nil {
		return asn1.RawValue{}, err
	}
	rv.FullBytes = full
	return rv, nil
}

// extractIA5StringSeq decodes a SEQUENCE OF IA5String captured as an
// asn1.RawValue. We walk the inner bytes element-by-element rather than
// relying on a `[]string` field because encoding/asn1 cannot tag slice
// elements as IA5String — the only way to round-trip cleanly is by hand.
func extractIA5StringSeq(rv asn1.RawValue) ([]string, error) {
	// An empty/unset RawValue (FullBytes nil) means the field was absent,
	// which is fine — return zero strings.
	if len(rv.FullBytes) == 0 {
		return nil, nil
	}
	// rv.Bytes is the SEQUENCE content (excluding the SEQUENCE header).
	// asn1.Unmarshal of the inner sequence-of pulls element-by-element.
	body := rv.Bytes
	var out []string
	for len(body) > 0 {
		var elem asn1.RawValue
		rest, err := asn1.Unmarshal(body, &elem)
		if err != nil {
			return nil, err
		}
		// Tag 22 == IA5String. Other string tags (PrintableString=19,
		// UTF8String=12) appear in the wild from sloppy CAs; accept them
		// but record nothing more strict — the operator gets the URI either
		// way.
		out = append(out, string(elem.Bytes))
		body = rest
	}
	return out, nil
}
