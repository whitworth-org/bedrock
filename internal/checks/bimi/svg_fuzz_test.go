package bimi

import (
	"testing"
)

// FuzzValidateTinyPS fuzzes the SVG parser entry point with arbitrary SVG content.
// This tests the XML parsing, profile validation, and security checks for
// script, external references, and viewBox validation.
func FuzzValidateTinyPS(f *testing.F) {
	// Add seed corpus with some basic SVG examples
	f.Add(`<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 100 100">
	<circle cx="50" cy="50" r="40" fill="blue"/>
</svg>`)

	f.Add(`<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 200 200">
	<rect x="10" y="10" width="180" height="180" fill="red"/>
</svg>`)

	f.Add(`<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 50 50">
	<path d="M 10 10 L 40 40" stroke="green" stroke-width="2"/>
</svg>`)

	// Malformed/attack vectors
	f.Add(`<script>alert(1)</script>`)
	f.Add(`<svg><image href="http://evil.com/img.png"/></svg>`)
	f.Add(`<svg onclick="alert(1)"></svg>`)

	f.Fuzz(func(t *testing.T, data string) {
		// Call the SVG validator - it should never panic regardless of input
		_ = ValidateTinyPS([]byte(data))
	})
}
