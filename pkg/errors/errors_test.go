package errors

import (
	"errors"
	"strings"
	"testing"
)

func TestExtendError(t *testing.T) {
	baseErr := errors.New("base error")

	t.Run("Wrap and Unwrap", func(t *testing.T) {
		infraErr := InfraError(baseErr)

		if !Is(baseErr, infraErr) {
			t.Error("Expected infraErr to be baseErr")
		}

		if !errors.Is(infraErr, baseErr) {
			t.Error("Expected infraErr to wrap baseErr")
		}

		unwrapped := errors.Unwrap(infraErr)
		if unwrapped != baseErr {
			t.Errorf("Expected unwrapped error to be baseErr, got %v", unwrapped)
		}
	})

	t.Run("Code and Metadata", func(t *testing.T) {
		err := AppError(baseErr).
			WithCode("APP_ERR_001").
			WithMetadata("userID", 123)

		if err.Code != "APP_ERR_001" {
			t.Errorf("Expected code 'APP_ERR_001', got %s", err.Code)
		}

		if val, ok := err.Metadata["userID"]; !ok || val != 123 {
			t.Errorf("Expected metadata userID=123, got %v", val)
		}

		// Check string representation
		expectedMsg := "[APP_ERR_001] base error"
		if err.Error() != expectedMsg {
			t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
		}
	})

	t.Run("StackTrace", func(t *testing.T) {
		err := DomainError(baseErr)
		if err.StackTrace == "" {
			t.Error("Expected stack trace to be present")
		}
		// Stack trace should contain this file name
		if !strings.Contains(err.StackTrace, "errors_test.go") {
			t.Error("Expected stack trace to contain test file name")
		}
	})

	t.Run("Helper Functions", func(t *testing.T) {
		infraErr := InfraError(baseErr)
		if !IsInfraError(infraErr) {
			t.Error("Expected IsInfraError to return true")
		}

		appErr := AppError(baseErr)
		if !IsAppError(appErr) {
			t.Error("Expected IsAppError to return true")
		}
	})
}
