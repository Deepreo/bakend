package errors

import (
	errs "errors"
	"fmt"
	"runtime"
	"strings"
)

type ErrorLevel string

func (e ErrorLevel) String() string {
	return string(e)
}

const (
	ERR_INFRASTRUCTURE ErrorLevel = "infrastructure"
	ERR_APPLICATION    ErrorLevel = "application"
	ERR_DOMAIN         ErrorLevel = "domain"
	ERR_VALIDATION     ErrorLevel = "validation"
	ERR_UNKNOWN        ErrorLevel = "unknown"
	ERR_AUTH           ErrorLevel = "auth"
	ERR_PERMISSION     ErrorLevel = "permission"
)

type ExtendError struct {
	Level      ErrorLevel     `json:"level"`
	Err        error          `json:"error"`
	Code       string         `json:"code,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	StackTrace string         `json:"-"`
}

func (e *ExtendError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	msg := e.Err.Error()
	if e.Code != "" {
		msg = fmt.Sprintf("[%s] %s", e.Code, msg)
	}
	return msg
}

func (e *ExtendError) Unwrap() error {
	return e.Err
}

func (e *ExtendError) WithCode(code string) *ExtendError {
	e.Code = code
	return e
}

func (e *ExtendError) WithMetadata(key string, value any) *ExtendError {
	if e.Metadata == nil {
		e.Metadata = make(map[string]any)
	}
	e.Metadata[key] = value
	return e
}

func New(message string) error {
	return errs.New(message)
}

func Is(target, err error) bool {
	return errs.Is(err, target)
}

func IsExtendError(err error) bool {
	var extendErr *ExtendError
	return errs.As(err, &extendErr)
}

func As(err error, target interface{}) bool {
	return errs.As(err, target)
}

func captureStackTrace() string {
	var sb strings.Builder
	// Skip 3 frames: captureStackTrace, wrap, and the caller of wrap
	for i := 3; i < 15; i++ {
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		fmt.Fprintf(&sb, "%s:%d\n", file, line)
	}
	return sb.String()
}

func wrap(err error, level ErrorLevel) *ExtendError {
	if IsExtendError(err) {
		// If it's already an ExtendError, we might want to update the level or just return it.
		// For now, let's just return it to preserve existing metadata/code.
		// If we want to override level, we can do: err.(*ExtendError).Level = level
		return err.(*ExtendError)
	}
	return &ExtendError{
		Level:      level,
		Err:        err,
		StackTrace: captureStackTrace(),
	}
}

func InfraError(err error) *ExtendError {
	return wrap(err, ERR_INFRASTRUCTURE)
}

func AppError(err error) *ExtendError {
	return wrap(err, ERR_APPLICATION)
}

func DomainError(err error) *ExtendError {
	return wrap(err, ERR_DOMAIN)
}

func ValidationError(err error) *ExtendError {
	return wrap(err, ERR_VALIDATION)
}

func UnknownError(err error) *ExtendError {
	return wrap(err, ERR_UNKNOWN)
}

func AuthError(err error) *ExtendError {
	return wrap(err, ERR_AUTH)
}

func PermissionError(err error) *ExtendError {
	return wrap(err, ERR_PERMISSION)
}

func getErrorLevel(err *ExtendError) ErrorLevel {
	if err == nil {
		return ERR_UNKNOWN
	}
	return err.Level
}

func GetLevel(err error) ErrorLevel {
	if IsExtendError(err) {
		return getErrorLevel(err.(*ExtendError))
	}
	return ERR_UNKNOWN
}

func IsInfraError(err *ExtendError) bool {
	return getErrorLevel(err) == ERR_INFRASTRUCTURE
}
func IsAppError(err *ExtendError) bool {
	return getErrorLevel(err) == ERR_APPLICATION
}
func IsAuthError(err *ExtendError) bool {
	return getErrorLevel(err) == ERR_AUTH
}
func IsPermissionError(err *ExtendError) bool {
	return getErrorLevel(err) == ERR_PERMISSION
}
func IsDomainError(err *ExtendError) bool {
	return getErrorLevel(err) == ERR_DOMAIN
}

func IsValidationError(err *ExtendError) bool {
	return getErrorLevel(err) == ERR_VALIDATION
}
func IsUnknownError(err *ExtendError) bool {
	return getErrorLevel(err) == ERR_UNKNOWN
}
