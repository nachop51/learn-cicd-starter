package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "No Authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Malformed header - missing ApiKey prefix",
			headers: http.Header{"Authorization": []string{"Bearer somekey"}},
			wantKey: "",
			wantErr: ErrMalformedHeader(),
		},
		{
			name:    "Malformed header - missing key",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantKey: "",
			wantErr: ErrMalformedHeader(),
		},
		{
			name:    "Valid ApiKey header",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-keye",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if key != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, key)
			}
			if tt.wantErr != nil {
				if err == nil || err.Error() != tt.wantErr.Error() {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// helper for error comparison
func ErrMalformedHeader() error {
	return errors.New("malformed authorization header")
}
