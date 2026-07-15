package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/kodeart/identity-sdk-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func IdentityAuth(client *identity.Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp, err := client.ValidateSession(r.Context(), getAuthToken(r))
			if err != nil {
				st, _ := status.FromError(err)
				switch st.Code() {
				case codes.Unimplemented, codes.Unavailable:
					err = status.Error(codes.Unavailable, "identity service is unreachable")
				case codes.Internal, codes.Unknown:
					err = status.Error(codes.Internal, "identity service internal error")
				}
				identity.AsProblem(r, err).JSON(w)
				return
			}
			ctx := context.WithValue(r.Context(), identity.UserContextKey, resp)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func getAuthToken(r *http.Request) string {
	c, err := r.Cookie("access_token")
	if err == nil {
		return c.Value
	}
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}
