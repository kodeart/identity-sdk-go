package identity

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/kodeart/go-problem/v2"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AsProblem converts a gRPC error to a problem.Problem
// and attaches request-specific information if any.
func AsProblem(r *http.Request, err error) *problem.Problem {
	st := status.Convert(err)
	rawMsg := st.Message()
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	p := &problem.Problem{
		Status:   CodeToHttpStatus(st.Code()),
		Instance: fmt.Sprintf(" %s://%s%s", scheme, r.Host, r.RequestURI),
		Detail:   rawMsg,
		Title:    st.Code().String(),
		Type:     getType(st.Code(), scheme, r.Host),
	}
	if idx := strings.Index(rawMsg, "{"); idx != -1 {
		jsonPart := rawMsg[idx:]
		var rawData map[string]any
		if jsonErr := json.Unmarshal([]byte(jsonPart), &rawData); jsonErr == nil {
			p.WithExtension("errors", rawData)
			p.Detail = strings.Trim(rawMsg[:idx], ": ")
			if p.Detail == "" {
				p.Detail = "The identity provider returned as error"
			}
		}
	}
	// Extract SDK details (BadRequest / FieldViolations)
	for _, detail := range st.Details() {
		if t, ok := detail.(*errdetails.BadRequest); ok {
			p.Type = getType(codes.InvalidArgument, scheme, r.Host)
			for _, v := range t.GetFieldViolations() {
				p.WithExtension(v.GetField(), v.GetDescription())
			}
		}
	}
	return p
}

// CodeToHttpStatus converts gRPC error code
// to its corresponding HTTP status code.
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

// getType returns a URI indicating the type of
// error based on the provided gRPC error code.
func getType(code codes.Code, scheme string, host string) string {
	var t string
	switch code {
	case codes.Unauthenticated:
		t = "invalid-session"
	case codes.InvalidArgument:
		t = "validation-failed"
	case codes.DeadlineExceeded:
		t = "gateway-timeout"
	case codes.Unavailable:
		t = "service-unavailable"
	case codes.FailedPrecondition:
		t = "service-error"
	default:
		t = "internal-error" // Unknown
	}
	return fmt.Sprintf("%s://%s/errors/%s", scheme, host, t)
}
