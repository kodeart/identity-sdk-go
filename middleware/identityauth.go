package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kodeart/identity-sdk-go"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kodeart/identity-sdk-go/proto/identity/v1"
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
				identity.AsProblem(err).JSON(w)
				return
			}
			ctx := context.WithValue(r.Context(), identity.UserContextKey, resp)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func IdentityAuthAutoRefresh(client *identity.Client, secretKey []byte, issuer string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := getAuthToken(r)
			if token == "" {
				next.ServeHTTP(w, r)
				return
			}

			info, err := identity.VerifyToken(token, secretKey, issuer)
			if err == nil {
				ctx := context.WithValue(r.Context(), identity.UserContextKey, newSessionResp(token, info))
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if !errors.Is(err, jwt.ErrTokenExpired) {
				log.Warn().Err(err).Msg("jwt auth: invalid token")
				next.ServeHTTP(w, r)
				return
			}

			refreshCookie, err := r.Cookie("refresh_token")
			if err != nil {
				log.Warn().Msg("jwt auth: expired token, no refresh cookie")
				next.ServeHTTP(w, r)
				return
			}

			resp, err := client.RefreshToken(r.Context(), refreshCookie.Value)
			if err != nil {
				log.Warn().Err(err).Msg("jwt auth: auto-refresh failed")
				next.ServeHTTP(w, r)
				return
			}

			setAuthCookies(w, resp.AccessToken, resp.RefreshToken)

			info, err = identity.VerifyToken(resp.AccessToken, secretKey, issuer)
			if err != nil {
				log.Warn().Err(err).Msg("jwt auth: auto-refreshed token invalid")
				next.ServeHTTP(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), identity.UserContextKey, newSessionResp(resp.AccessToken, info))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func newSessionResp(token string, info *identity.TokenInfo) *pb.ValidateSessionResponse {
	return &pb.ValidateSessionResponse{
		AccessToken: token,
		UserId:      info.UserID,
		ExpiresAt:   info.ExpiresAt,
	}
}

func setAuthCookies(w http.ResponseWriter, accessToken, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func getAuthToken(r *http.Request) string {
	c, err := r.Cookie("access_token")
	if err == nil {
		return c.Value
	}
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}
