package kvm

import (
	"net/http"
	"testing"
)

func TestRedfishAllowableResetTypes(t *testing.T) {
	orig := config
	t.Cleanup(func() { config = orig })

	tests := []struct {
		ext  string
		want int
	}{
		{"dc-power", 5},
		{"atx-power", 7},
		{"", 0},
		{"unknown-ext", 0},
	}
	for _, tc := range tests {
		config = &Config{ActiveExtension: tc.ext}
		if got := len(redfishAllowableResetTypes()); got != tc.want {
			t.Errorf("ActiveExtension=%q: got %d reset types, want %d", tc.ext, got, tc.want)
		}
	}
}

func TestPerformRedfishResetDispatch(t *testing.T) {
	orig := config
	t.Cleanup(func() { config = orig })

	// No power extension loaded -> 503 Service Unavailable.
	config = &Config{ActiveExtension: ""}
	if status, err := performRedfishReset("On"); status != http.StatusServiceUnavailable || err == nil {
		t.Errorf("no extension: got (%d, %v), want (503, error)", status, err)
	}

	// Unsupported ResetType is rejected with 400 before touching hardware.
	config = &Config{ActiveExtension: "dc-power"}
	if status, err := performRedfishReset("Nmi"); status != http.StatusBadRequest || err == nil {
		t.Errorf("dc-power invalid ResetType: got (%d, %v), want (400, error)", status, err)
	}
	config = &Config{ActiveExtension: "atx-power"}
	if status, err := performRedfishReset("Nmi"); status != http.StatusBadRequest || err == nil {
		t.Errorf("atx-power invalid ResetType: got (%d, %v), want (400, error)", status, err)
	}
}
