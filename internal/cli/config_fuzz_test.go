package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadConfig fuzzes the config JSON loader with arbitrary JSON content.
// This tests JSON parsing, unknown field detection, size limits, and
// validation of multiple JSON values in a single file.
func FuzzLoadConfig(f *testing.F) {
	// Add seed corpus with valid config JSON
	f.Add([]byte(`{"no_color":true,"timeout":"10s","only":["dns","email"]}`))

	// Add edge cases
	f.Add([]byte(`{}`))                                  // Empty object
	f.Add([]byte(`{"no_color":false}`))                  // Single field
	f.Add([]byte(`{"resolvers":["1.1.1.1","8.8.8.8"]}`)) // Array field

	// Add malformed JSON
	f.Add([]byte(`{`))                         // Incomplete
	f.Add([]byte(`{"no_color":}`))             // Invalid syntax
	f.Add([]byte(`{"unknown_field":"value"}`)) // Unknown field

	// Add multiple JSON values
	f.Add([]byte(`{"no_color":true}{"timeout":"10s"}`)) // Two objects
	f.Add([]byte(`{}[]`))                               // Object followed by array

	// Add various data types
	f.Add([]byte(`{"no_color":true,"timeout":"10s","only":["dns"],"subdomains":false}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a temporary file with the fuzz data
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			// If we can't write the file, skip this test case
			t.Skip("Unable to create temp file")
		}

		// Call the config loader - it should never panic regardless of input
		_, _ = LoadConfig(path)
	})
}
