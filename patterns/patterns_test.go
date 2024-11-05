package patterns

import (
	"regexp"
	"testing"
)

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     float64
		wantHigh bool
	}{
		{
			name:     "High entropy string",
			input:    "aB3$xK9#mP",
			wantHigh: true,
		},
		{
			name:     "Low entropy string",
			input:    "aaaaaaaaaa",
			wantHigh: false,
		},
		{
			name:     "Empty string",
			input:    "",
			want:     0,
			wantHigh: false,
		},
		{
			name:     "API key like string",
			input:    "AIzaSyC93b6FxR4r4Q1jI",
			wantHigh: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateEntropy(tt.input)
			if tt.want != 0 && got != tt.want {
				t.Errorf("CalculateEntropy() = %v, want %v", got, tt.want)
			}
			if tt.wantHigh && got < 3.0 {
				t.Errorf("Expected high entropy (>3.0), got %v", got)
			}
			if !tt.wantHigh && got > 3.0 {
				t.Errorf("Expected low entropy (<3.0), got %v", got)
			}
		})
	}
}

func TestIsLikelySecret(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		entropyThreshold float64
		want             bool
	}{
		{
			name:             "Valid API key",
			input:            "AIzaSyC93b6FxR4r4Q1jI",
			entropyThreshold: 3.5,
			want:             true,
		},
		{
			name:             "Common word",
			input:            "password",
			entropyThreshold: 3.5,
			want:             false,
		},
		{
			name:             "Too short",
			input:            "abc123",
			entropyThreshold: 3.5,
			want:             false,
		},
		{
			name:             "Complex password",
			input:            "MyP@ssw0rd123!",
			entropyThreshold: 3.5,
			want:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLikelySecret(tt.input, tt.entropyThreshold); got != tt.want {
				t.Errorf("IsLikelySecret() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPatternMatching(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		text    string
		want    bool
	}{
		{
			name:    "AWS Access Key",
			pattern: CommonAPIPatterns["aws_access_key"],
			text:    "AKIAIOSFODNN7EXAMPLE",
			want:    true,
		},
		{
			name:    "GitHub Token",
			pattern: CommonAPIPatterns["github_token"],
			text:    "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
			want:    true,
		},
		{
			name:    "Invalid AWS Key",
			pattern: CommonAPIPatterns["aws_access_key"],
			text:    "NOTANACCESSKEY",
			want:    false,
		},
		{
			name:    "Basic Password",
			pattern: PasswordPatterns["basic_password"],
			text:    "password='MySecretPass123'",
			want:    true,
		},
		{
			name:    "RSA Private Key",
			pattern: PrivateKeyPatterns["rsa_private"],
			text:    "-----BEGIN RSA PRIVATE KEY-----\ndata",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re := regexp.MustCompile(tt.pattern)
			got := re.MatchString(tt.text)
			if got != tt.want {
				t.Errorf("Pattern match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAllPatterns(t *testing.T) {
	patterns := GetAllPatterns()

	// Check if all pattern types are included
	expectedCount := len(CommonAPIPatterns) + len(PasswordPatterns) + len(PrivateKeyPatterns)
	if len(patterns) != expectedCount {
		t.Errorf("GetAllPatterns() returned %d patterns, want %d", len(patterns), expectedCount)
	}

	// Verify that patterns are valid regular expressions
	for name, pattern := range patterns {
		_, err := regexp.Compile(pattern)
		if err != nil {
			t.Errorf("Invalid pattern %s: %v", name, err)
		}
	}
}
