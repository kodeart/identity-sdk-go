package middleware

import (
	"context"
	"net/http"

	"github.com/kodeart/go-problem/v2"
	identity "github.com/kodeart/identity-sdk-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RequirePermission composes AFTER AuthHTTP: rejects 401 when no authenticated
// user is in context, 403 when the user lacks perm, else continues.
func RequirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			su := identity.GetUser(r.Context())
			if su == nil {
				respondProblem(w, r, http.StatusUnauthorized, "not authenticated")
				return
			}
			if !identity.Can(su, perm) {
				respondProblem(w, r, http.StatusForbidden, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func respondProblem(w http.ResponseWriter, r *http.Request, status int, detail string) {
	problem.New().
		WithStatus(status).
		WithInstance(r.URL.String()).
		WithTitle(http.StatusText(status)).
		WithDetail(detail).
		JSON(w)
}

// RequirePermissionGRPC is the same gate as a UnaryServerInterceptor: rejects
// Unauthenticated when no authenticated user is in context, PermissionDenied
// when the user lacks perm.
func RequirePermissionGRPC(perm string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		su := identity.GetUser(ctx)
		if su == nil {
			return nil, status.Error(codes.Unauthenticated, "not authenticated")
		}
		if !identity.Can(su, perm) {
			return nil, status.Error(codes.PermissionDenied, "forbidden")
		}
		return handler(ctx, req)
	}
}
