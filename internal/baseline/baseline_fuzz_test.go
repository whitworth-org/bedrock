package baseline

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad fuzzes the baseline JSON loader with arbitrary JSON content.
// This tests JSON parsing, unknown field detection, size limits, and
// validation of the baseline data structure.
func FuzzLoad(f *testing.F) {
	// Add seed corpus with valid baseline JSON
	f.Add([]byte(`{"entries":[{"id":"dns.basic","category":"DNS","status":"PASS"}]}`))

	// Add edge cases
	f.Add([]byte(`{}`))               // Empty object
	f.Add([]byte(`{"entries":[]}`))   // Empty entries
	f.Add([]byte(`{"entries":[{}]}`)) // Empty entry

	// Add malformed JSON
	f.Add([]byte(`{`))                         // Incomplete
	f.Add([]byte(`{"entries":}`))              // Invalid syntax
	f.Add([]byte(`{"unknown_field":"value"}`)) // Unknown field

	// Add large JSON
	f.Add([]byte(`{"entries":[` +
		`{"id":"test1","category":"DNS","status":"PASS"},` +
		`{"id":"test2","category":"Email","status":"FAIL"}` +
		`]}`))

	// Add nested objects
	f.Add([]byte(`{"entries":[{"id":"test","category":"DNS","status":"PASS","nested":{"field":"value"}}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a temporary file with the fuzz data
		dir := t.TempDir()
		path := filepath.Join(dir, "baseline.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			// If we can't write the file, skip this test case
			t.Skip("Unable to create temp file")
		}

		// Call the baseline loader - it should never panic regardless of input
		_, _ = Load(path)
	})
}
