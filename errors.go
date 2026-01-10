package identity

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kodeart/go-problem/v2"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ProviderError represents an error structure returned by an
// identity provider, which may include generic or detailed errors.
type ProviderError struct {
	// Generic style (i.e. Firebase, etc)
	Error string `json:"error"`
	// Clerk format
	Errors []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// AsProblem converts a gRPC error to a problem.Problem
// and attaches request-specific information if any.
func AsProblem(r *http.Request, err error) *problem.Problem {
	st := status.Convert(err)
	msg := st.Message()
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	p := &problem.Problem{
		Status:   CodeToHttpStatus(st.Code()),
		Instance: fmt.Sprintf(" %s://%s%s", scheme, r.Host, r.RequestURI),
		Detail:   msg,
		Title:    st.Code().String(),
	}
	errs := make(map[string]any)
	if json.Valid([]byte(msg)) {
		var pErr ProviderError
		if jsonErr := json.Unmarshal([]byte(msg), &pErr); jsonErr == nil {
			p.Detail = "The identity provicer returned as error"
			for _, e := range pErr.Errors {
				errs[e.Code] = e.Message
			}
		}
	}
	// Extract SDK details (BadRequest / FieldViolations)
	for _, detail := range st.Details() {
		if t, ok := detail.(*errdetails.BadRequest); ok {
			for _, v := range t.GetFieldViolations() {
				errs[v.GetField()] = v.GetDescription()
			}
		}
	}
	if len(errs) > 0 {
		p.WithExtension("errors", errs)
	}
	return p
}

// CodeToHttpStatus converts gRPC error code to its corresponding HTTP status code.
func CodeToHttpStatus(code codes.Code) int {
	switch code {
	case codes.OK:
		return http.StatusOK
	case codes.InvalidArgument:
		return http.StatusBadRequest
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.PermissionDenied:
		return http.StatusForbidden
	case codes.NotFound:
		return http.StatusNotFound
	case codes.AlreadyExists:
		return http.StatusConflict
	case codes.FailedPrecondition:
		return http.StatusUnprocessableEntity
	case codes.ResourceExhausted:
		return http.StatusTooManyRequests
	case codes.Unavailable:
		return http.StatusServiceUnavailable
	case codes.DeadlineExceeded:
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}
