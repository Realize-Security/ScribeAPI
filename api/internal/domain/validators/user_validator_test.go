package validators

import (
	"Scribe/internal/domain/entities"
	"Scribe/pkg/config"
	"reflect"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
)

// Helper function to create a mock FieldLevel
type mockFieldLevel struct {
	field  reflect.Value
	parent reflect.Value
}

func (m *mockFieldLevel) Field() reflect.Value {
	return m.field
}

func (m *mockFieldLevel) Parent() reflect.Value {
	return m.parent
}

func (m *mockFieldLevel) Top() reflect.Value {
	return reflect.Value{}
}

func (m *mockFieldLevel) FieldName() string {
	return ""
}

func (m *mockFieldLevel) StructFieldName() string {
	return ""
}

func (m *mockFieldLevel) Param() string {
	return ""
}

func (m *mockFieldLevel) GetTag() string {
	return ""
}

func (m *mockFieldLevel) ExtractType(field reflect.Value) (reflect.Value, reflect.Kind, bool) {
	return reflect.Value{}, reflect.Invalid, false
}

func (m *mockFieldLevel) GetStructFieldOK() (reflect.Value, reflect.Kind, bool) {
	return reflect.Value{}, reflect.Invalid, false
}

func (m *mockFieldLevel) GetStructFieldOKAdvanced(val reflect.Value, namespace string) (reflect.Value, reflect.Kind, bool) {
	return reflect.Value{}, reflect.Invalid, false
}

func (m *mockFieldLevel) GetStructFieldOK2() (reflect.Value, reflect.Kind, bool, bool) {
	return reflect.Value{}, reflect.Invalid, false, false
}

func (m *mockFieldLevel) GetStructFieldOKAdvanced2(val reflect.Value, namespace string) (reflect.Value, reflect.Kind, bool, bool) {
	return reflect.Value{}, reflect.Invalid, false, false
}

func TestNameLength(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Valid name within range", "John", true},
		{"Name at minimum length", "J", true},                     // MinUserLen = 1
		{"Name at maximum length", strings.Repeat("a", 30), true}, // MaxUserLen = 30
		{"Name too long", strings.Repeat("a", 31), false},         // > MaxUserLen
		{"Empty name", "", false},                                 // < MinUserLen
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl := &mockFieldLevel{
				field: reflect.ValueOf(tt.input),
			}
			result := nameLength(fl)
			if result != tt.expected {
				t.Errorf("nameLength() = %v, expected %v for input %q", result, tt.expected, tt.input)
			}
		})
	}
}

func TestNamePattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Simple valid name", "John", true},
		{"Name with hyphen", "Jean-Pierre", true},
		{"Name with apostrophe", "O'Connor", true},
		{"Name with space", "Mary Jane", true},
		{"Name with accented characters", "José", true},
		{"Name with mixed case", "McDonald", true},
		{"Name with period", "Jr. Smith", false},
		{"Multiple spaces", "John  Doe", false},
		{"Starting with number", "1John", false},
		{"Special characters", "John@Doe", false},
		{"Starting with space", " John", false},
		{"Ending with space", "John ", false},
		{"Starting with hyphen", "-John", false},
		{"Empty string", "", true}, // Empty string matches the optional pattern
		{"Only special characters", "@#$", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl := &mockFieldLevel{
				field: reflect.ValueOf(tt.input),
			}
			result := namePattern(fl)
			if result != tt.expected {
				t.Errorf("namePattern() = %v, expected %v for input %q", result, tt.expected, tt.input)
			}
		})
	}
}

func TestPasswordsMatch(t *testing.T) {
	tests := []struct {
		name     string
		user     entities.UserRegistration
		expected bool
	}{
		{
			name: "Passwords match",
			user: entities.UserRegistration{
				Password:        "password123",
				ConfirmPassword: "password123",
			},
			expected: true,
		},
		{
			name: "Passwords don't match",
			user: entities.UserRegistration{
				Password:        "password123",
				ConfirmPassword: "password456",
			},
			expected: false,
		},
		{
			name: "Empty passwords match",
			user: entities.UserRegistration{
				Password:        "",
				ConfirmPassword: "",
			},
			expected: true,
		},
		{
			name: "One empty password",
			user: entities.UserRegistration{
				Password:        "password123",
				ConfirmPassword: "",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl := &mockFieldLevel{
				parent: reflect.ValueOf(tt.user),
			}
			result := passwordsMatch(fl)
			if result != tt.expected {
				t.Errorf("passwordsMatch() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestPasswordsMatchWithInvalidParent(t *testing.T) {
	// Test case where parent is not UserRegistration
	fl := &mockFieldLevel{
		parent: reflect.ValueOf("invalid"),
	}
	result := passwordsMatch(fl)
	if result != false {
		t.Errorf("passwordsMatch() with invalid parent = %v, expected false", result)
	}
}

func TestPasswordLength(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Valid password", "supersecretpassword123", true},
		{"Password at minimum length", strings.Repeat("a", config.MinPasswordLength), true},
		{"Password too short", "pass", false},
		{"Empty password", "", false},
		{"Long password", strings.Repeat("a", 100), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl := &mockFieldLevel{
				field: reflect.ValueOf(tt.input),
			}
			result := passwordLength(fl)
			if result != tt.expected {
				t.Errorf("passwordLength() = %v, expected %v for input %q", result, tt.expected, tt.input)
			}
		})
	}
}

func TestEmailNotInPassword(t *testing.T) {
	tests := []struct {
		name     string
		user     entities.UserRegistration
		expected bool
	}{
		{
			name: "Email not in password",
			user: entities.UserRegistration{
				Email:    "user@example.com",
				Password: "securepassword123",
			},
			expected: true,
		},
		{
			name: "Email in password",
			user: entities.UserRegistration{
				Email:    "user@example.com",
				Password: "user@example.com123",
			},
			expected: false,
		},
		{
			name: "Reversed email in password",
			user: entities.UserRegistration{
				Email:    "user@example.com",
				Password: "moc.elpmaxe@resu123",
			},
			expected: false,
		},
		{
			name: "Email in password with different case",
			user: entities.UserRegistration{
				Email:    "User@Example.Com",
				Password: "user@example.com123",
			},
			expected: false,
		},
		{
			name: "Partial email in password",
			user: entities.UserRegistration{
				Email:    "user@example.com",
				Password: "userexample123",
			},
			expected: true,
		},
		{
			name: "Empty email and password",
			user: entities.UserRegistration{
				Email:    "",
				Password: "",
			},
			expected: false,
		},
		{
			name: "Empty email",
			user: entities.UserRegistration{
				Email:    "",
				Password: "password123",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl := &mockFieldLevel{
				parent: reflect.ValueOf(tt.user),
			}
			result := emailNotInPassword(fl)
			if result != tt.expected {
				t.Errorf("emailNotInPassword() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestEmailNotInPasswordWithInvalidParent(t *testing.T) {
	// Test case where parent is not UserRegistration
	fl := &mockFieldLevel{
		parent: reflect.ValueOf("invalid"),
	}
	result := emailNotInPassword(fl)
	if result != false {
		t.Errorf("emailNotInPassword() with invalid parent = %v, expected false", result)
	}
}

func TestReverseString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Simple string", "hello", "olleh"},
		{"Empty string", "", ""},
		{"Single character", "a", "a"},
		{"String with numbers", "abc123", "321cba"},
		{"String with special characters", "hello@world.com", "moc.dlrow@olleh"},
		{"Unicode characters", "José", "ésoJ"},
		{"Palindrome", "racecar", "racecar"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reverseString(tt.input)
			if result != tt.expected {
				t.Errorf("reverseString(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// Integration test with actual validator
func TestValidatorsWithRealValidator(t *testing.T) {
	v := validator.New()

	// Register custom validators
	v.RegisterValidation("name_length", nameLength)
	v.RegisterValidation("name_pattern", namePattern)
	v.RegisterValidation("passwords_match", passwordsMatch)
	v.RegisterValidation("password_length", passwordLength)
	v.RegisterValidation("email_not_in_password", emailNotInPassword)

	// Test struct with validation tags matching UserRegistration
	type TestUser struct {
		FirstName       string `validate:"required,name_length,name_pattern"`
		LastName        string `validate:"required,name_length,name_pattern"`
		Email           string `validate:"required,email"`
		Password        string `validate:"required,passwords_match,password_length"`
		ConfirmPassword string `validate:"required"`
		TermsAccepted   bool   `validate:"required"`
	}

	tests := []struct {
		name      string
		user      entities.UserRegistration
		shouldErr bool
	}{
		{
			name: "Valid user",
			user: entities.UserRegistration{
				FirstName:       "John",
				LastName:        "Doe",
				Email:           "john@example.com",
				Password:        "securepassword123",
				ConfirmPassword: "securepassword123",
				TermsAccepted:   true,
			},
			shouldErr: false,
		},
		{
			name: "Invalid first name pattern",
			user: entities.UserRegistration{
				FirstName:       "John123",
				LastName:        "Doe",
				Email:           "john@example.com",
				Password:        "securepassword123",
				ConfirmPassword: "securepassword123",
				TermsAccepted:   true,
			},
			shouldErr: true,
		},
		{
			name: "Invalid last name pattern",
			user: entities.UserRegistration{
				FirstName:       "John",
				LastName:        "Doe@123",
				Email:           "john@example.com",
				Password:        "securepassword123",
				ConfirmPassword: "securepassword123",
				TermsAccepted:   true,
			},
			shouldErr: true,
		},
		{
			name: "First name too long",
			user: entities.UserRegistration{
				FirstName:       strings.Repeat("a", 31), // > MaxUserLen
				LastName:        "Doe",
				Email:           "john@example.com",
				Password:        "securepassword123",
				ConfirmPassword: "securepassword123",
				TermsAccepted:   true,
			},
			shouldErr: true,
		},
		{
			name: "Password too short",
			user: entities.UserRegistration{
				FirstName:       "John",
				LastName:        "Doe",
				Email:           "john@example.com",
				Password:        "short",
				ConfirmPassword: "short",
				TermsAccepted:   true,
			},
			shouldErr: true,
		},
		{
			name: "Passwords don't match",
			user: entities.UserRegistration{
				FirstName:       "John",
				LastName:        "Doe",
				Email:           "john@example.com",
				Password:        "securepassword123",
				ConfirmPassword: "differentpassword",
				TermsAccepted:   true,
			},
			shouldErr: true,
		},
		{
			name: "Missing required field",
			user: entities.UserRegistration{
				FirstName:       "",
				LastName:        "Doe",
				Email:           "john@example.com",
				Password:        "securepassword123",
				ConfirmPassword: "securepassword123",
				TermsAccepted:   true,
			},
			shouldErr: true,
		},
		{
			name: "Terms not accepted",
			user: entities.UserRegistration{
				FirstName:       "John",
				LastName:        "Doe",
				Email:           "john@example.com",
				Password:        "securepassword123",
				ConfirmPassword: "securepassword123",
				TermsAccepted:   false,
			},
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(tt.user)
			hasErr := err != nil
			if hasErr != tt.shouldErr {
				t.Errorf("Validation error status = %v, expected %v. Error: %v", hasErr, tt.shouldErr, err)
			}
		})
	}
}
