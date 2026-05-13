package validator

import (
	"testing"
)

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		// Valid emails
		{"simple", "test@example.com", true},
		{"with_dots", "test.user@example.com", true},
		{"with_plus", "test+user@example.com", true},
		{"with_underscore", "test_user@example.com", true},
		{"with_hyphen", "test-user@example.com", true},
		{"with_percent", "test%user@example.com", true},
		{"subdomain", "test@mail.example.com", true},
		{"long_tld", "test@example.museum", true},
		{"numbers", "test123@example.com", true},
		{"mixed", "test.user+tag@example.co.uk", true},

		// Invalid emails
		{"no_at", "testexample.com", false},
		{"multiple_at", "test@@example.com", false},
		{"empty_local", "@example.com", false},
		{"empty_domain", "test@", false},
		{"no_tld", "test@example", false},
		{"single_char_tld", "test@example.c", false},
		{"dot_start_local", ".test@example.com", false},
		{"dot_end_local", "test.@example.com", false},
		{"dot_start_domain", "test@.example.com", false},
		{"dot_end_domain", "test@example.com.", false},
		{"hyphen_start_domain", "test@-example.com", false},
		{"hyphen_end_domain", "test@example-.com", false},
		{"empty", "", false},
		{"spaces", "test @example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateEmail(tt.email)
			if result != tt.expected {
				t.Errorf("ValidateEmail(%q) = %v, want %v", tt.email, result, tt.expected)
			}
		})
	}
}
