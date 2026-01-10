package identity

import (
	"fmt"
	"net/http"

	"github.com/kodeart/go-problem/v2"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// WithError converts a gRPC error to a problem.Problem
// and attaches request-specific information if any.
func WithError(r *http.Request, err error) *problem.Problem {
	st := status.Convert(err)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	p := &problem.Problem{
		Status:   CodeToHttpStatus(st.Code()),
		Instance: fmt.Sprintf(" %s://%s%s", scheme, r.Host, r.RequestURI),
		Detail:   st.Message(),
		Title:    st.Code().String(),
	}
	// Extract SDK details (BadRequest / FieldViolations)
	for _, detail := range st.Details() {
		if t, ok := detail.(*errdetails.BadRequest); ok {
			errs := make(map[string]any)
			for _, v := range t.GetFieldViolations() {
				errs[v.GetField()] = v.GetDescription()
			}
			p.WithExtension("errors", errs)
		}
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
