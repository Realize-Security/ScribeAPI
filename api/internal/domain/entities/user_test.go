package entities

import (
	"Scribe/handlers/http/dto/request"
	"testing"
)

func TestUserRegistration_Sanitize(t *testing.T) {
	tests := []struct {
		name     string
		input    request.UserRegistration
		expected request.UserRegistration
	}{
		{
			name: "trims whitespace from all string fields",
			input: request.UserRegistration{
				FirstName:       "  John  ",
				LastName:        "  Doe  ",
				Email:           "  JOHN@EXAMPLE.COM  ",
				Password:        "password123",
				ConfirmPassword: "password123",
				TermsAccepted:   true,
			},
			expected: request.UserRegistration{
				FirstName:       "John",
				LastName:        "Doe",
				Email:           "john@example.com",
				Password:        "password123",
				ConfirmPassword: "password123",
				TermsAccepted:   true,
			},
		},
		{
			name: "converts email to lowercase",
			input: request.UserRegistration{
				FirstName: "Jane",
				LastName:  "Smith",
				Email:     "JANE.SMITH@EXAMPLE.COM",
			},
			expected: request.UserRegistration{
				FirstName: "Jane",
				LastName:  "Smith",
				Email:     "jane.smith@example.com",
			},
		},
		{
			name: "handles mixed case email with whitespace",
			input: request.UserRegistration{
				FirstName: "Bob",
				LastName:  "Johnson",
				Email:     "  Bob.Johnson@Gmail.COM  ",
			},
			expected: request.UserRegistration{
				FirstName: "Bob",
				LastName:  "Johnson",
				Email:     "bob.johnson@gmail.com",
			},
		},
		{
			name: "handles empty strings",
			input: request.UserRegistration{
				FirstName: "",
				LastName:  "",
				Email:     "",
			},
			expected: request.UserRegistration{
				FirstName: "",
				LastName:  "",
				Email:     "",
			},
		},
		{
			name: "handles strings with only whitespace",
			input: request.UserRegistration{
				FirstName: "   ",
				LastName:  "\t\n",
				Email:     "  \r\n  ",
			},
			expected: request.UserRegistration{
				FirstName: "",
				LastName:  "",
				Email:     "",
			},
		},
		{
			name: "preserves password fields unchanged",
			input: request.UserRegistration{
				FirstName:       "Alice",
				LastName:        "Wonder",
				Email:           "alice@example.com",
				Password:        "  mySecretPassword  ",
				ConfirmPassword: "  mySecretPassword  ",
			},
			expected: request.UserRegistration{
				FirstName:       "Alice",
				LastName:        "Wonder",
				Email:           "alice@example.com",
				Password:        "  mySecretPassword  ",
				ConfirmPassword: "  mySecretPassword  ",
			},
		},
		{
			name: "handles special characters in names",
			input: request.UserRegistration{
				FirstName: "  José  ",
				LastName:  "  O'Connor  ",
				Email:     "  JOSE.OCONNOR@EXAMPLE.COM  ",
			},
			expected: request.UserRegistration{
				FirstName: "José",
				LastName:  "O'Connor",
				Email:     "jose.oconnor@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy to avoid modifying the test case
			user := tt.input
			user.CleanWhiteSpace()

			// Check each field
			if user.FirstName != tt.expected.FirstName {
				t.Errorf("FirstName = %q, expected %q", user.FirstName, tt.expected.FirstName)
			}
			if user.LastName != tt.expected.LastName {
				t.Errorf("LastName = %q, expected %q", user.LastName, tt.expected.LastName)
			}
			if user.Email != tt.expected.Email {
				t.Errorf("Email = %q, expected %q", user.Email, tt.expected.Email)
			}
			if user.Password != tt.expected.Password {
				t.Errorf("Password = %q, expected %q", user.Password, tt.expected.Password)
			}
			if user.ConfirmPassword != tt.expected.ConfirmPassword {
				t.Errorf("ConfirmPassword = %q, expected %q", user.ConfirmPassword, tt.expected.ConfirmPassword)
			}
			if user.TermsAccepted != tt.expected.TermsAccepted {
				t.Errorf("TermsAccepted = %v, expected %v", user.TermsAccepted, tt.expected.TermsAccepted)
			}
		})
	}
}

// Alternative test using table-driven approach with individual field checks
func TestUserRegistration_Sanitize_IndividualFields(t *testing.T) {
	testCases := []struct {
		description string
		field       string
		input       string
		expected    string
	}{
		{"FirstName with leading whitespace", "FirstName", "  John", "John"},
		{"FirstName with trailing whitespace", "FirstName", "John  ", "John"},
		{"FirstName with both", "FirstName", "  John  ", "John"},
		{"LastName with tabs and spaces", "LastName", "\t Doe \n", "Doe"},
		{"Email uppercase conversion", "Email", "JOHN@EXAMPLE.COM", "john@example.com"},
		{"Email with whitespace and case", "Email", "  JOHN@EXAMPLE.COM  ", "john@example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			user := &request.UserRegistration{}

			// Set the specific field
			switch tc.field {
			case "FirstName":
				user.FirstName = tc.input
			case "LastName":
				user.LastName = tc.input
			case "Email":
				user.Email = tc.input
			}

			user.CleanWhiteSpace()

			// Check the specific field
			var actual string
			switch tc.field {
			case "FirstName":
				actual = user.FirstName
			case "LastName":
				actual = user.LastName
			case "Email":
				actual = user.Email
			}

			if actual != tc.expected {
				t.Errorf("%s: got %q, expected %q", tc.field, actual, tc.expected)
			}
		})
	}
}

// Benchmark test to ensure performance is acceptable
func BenchmarkUserRegistration_Sanitize(b *testing.B) {
	user := request.UserRegistration{
		FirstName:       "  John  ",
		LastName:        "  Doe  ",
		Email:           "  JOHN.DOE@EXAMPLE.COM  ",
		Password:        "password123",
		ConfirmPassword: "password123",
		TermsAccepted:   true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testUser := user
		testUser.CleanWhiteSpace()
	}
}
