package errors

import "fmt"

type Kind int

const (
	KindConfig Kind = iota + 1
	KindIO
	KindParse
	KindDetection
	KindScoring
	KindReport
	KindValidation
)

func (k Kind) String() string {
	switch k {
	case KindConfig:
		return "configuration"
	case KindIO:
		return "io"
	case KindParse:
		return "parse"
	case KindDetection:
		return "detection"
	case KindScoring:
		return "scoring"
	case KindReport:
		return "report"
	case KindValidation:
		return "validation"
	default:
		return "unknown"
	}
}

type SentinelError struct {
	Kind    Kind
	Module  string
	Message string
	Err     error
}

func (e *SentinelError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s:%s] %s: %v", e.Kind, e.Module, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s:%s] %s", e.Kind, e.Module, e.Message)
}

func (e *SentinelError) Unwrap() error {
	return e.Err
}

func New(kind Kind, module, message string, err error) *SentinelError {
	return &SentinelError{
		Kind:    kind,
		Module:  module,
		Message: message,
		Err:     err,
	}
}
