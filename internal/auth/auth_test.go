package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantAPIKey string
		wantErr    error
	}{
		{
			name:       "no authorization header",
			headers:    http.Header{},
			wantAPIKey: "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header missing key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name: "wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer somekey"},
			},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name: "valid api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey secret123"},
			},
			wantAPIKey: "secret123",
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if got != tt.wantAPIKey {
				t.Errorf("expected key %q, got %q", tt.wantAPIKey, got)
			}

			// Compare error messages instead of pointer equality
			if (err != nil && tt.wantErr == nil) ||
				(err == nil && tt.wantErr != nil) ||
				(err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error()) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}