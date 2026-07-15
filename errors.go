package identity

import (
	"net/http"

	"github.com/kodeart/go-problem/v2"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func AsProblem(err error) *problem.Problem {
	st := status.Convert(err)
	statusCode := codeToHttpStatus(st.Code())
	p := &problem.Problem{
		Status: statusCode,
		Detail: st.Message(),
		Title:  http.StatusText(statusCode),
	}

	for _, detail := range st.Details() {
		if t, ok := detail.(*errdetails.BadRequest); ok {
			for _, v := range t.GetFieldViolations() {
				p.WithExtension(v.GetField(), v.GetDescription())
			}
		}
	}
	return p
}

func codeToHttpStatus(code codes.Code) int {
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
	case codes.Unimplemented:
		return http.StatusNotImplemented
	default:
		return http.StatusInternalServerError
	}
}
