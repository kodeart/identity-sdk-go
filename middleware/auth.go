package middleware

import (
    "context"
    "errors"
    "net/http"
    "strings"

    "github.com/golang-jwt/jwt/v5"
    identity "github.com/kodeart/identity-sdk-go"
    "github.com/rs/zerolog/log"
    "google.golang.org/grpc"
    "google.golang.org/grpc/metadata"
)

// AuthHTTP is an HTTP middleware for REST apps consuming identity as a separate service.
// Local verify fast-path (HMAC + expiry check, zero network calls).
// On expiry: reads refresh_token cookie, calls RefreshToken via gRPC, sets new cookies.
// On any other failure: passes through without auth (public route compatible).
func AuthHTTP(client *identity.Client) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            token := GetAuthToken(r)
            if token == "" {
                next.ServeHTTP(w, r)
                return
            }

            su, err := identity.VerifyToken(token, []byte(client.Config.JWTSecretKey), client.Config.JWTIssuer)
            if err == nil {
                ctx := context.WithValue(r.Context(), identity.UserContextKey, su)
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
                log.Warn().Err(err).Msg("jwt auth: refresh failed")
                next.ServeHTTP(w, r)
                return
            }

            setAuthCookies(w, client.Config, resp.AccessToken, resp.RefreshToken)

            // TODO why VerifyToken here (second time) ?
            su, err = identity.VerifyToken(resp.AccessToken, []byte(client.Config.JWTSecretKey), client.Config.JWTIssuer)
            if err != nil {
                log.Warn().Err(err).Msg("jwt auth: refreshed token invalid")
                next.ServeHTTP(w, r)
                return
            }
            ctx := context.WithValue(r.Context(), identity.UserContextKey, su)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// AuthGRPC is a gRPC server interceptor for authenticating incoming gRPC calls.
// Local verify only (HMAC + expiry check). No refresh — gRPC has no cookie mechanism.
// Invalid or missing tokens log a warning and pass through (no rejection).
func AuthGRPC(client *identity.Client) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
        md, ok := metadata.FromIncomingContext(ctx)
        if !ok {
            return handler(ctx, req)
        }
        values := md.Get("authorization")
        if len(values) == 0 {
            return handler(ctx, req)
        }
        auth := values[0]
        if !strings.HasPrefix(auth, "Bearer ") {
            return handler(ctx, req)
        }
        token := strings.TrimPrefix(auth, "Bearer ")
        su, err := identity.VerifyToken(token, []byte(client.Config.JWTSecretKey), client.Config.JWTIssuer)
        if err != nil {
            log.Warn().Err(err).Msg("jwt auth: invalid token")
            return handler(ctx, req)
        }
        ctx = context.WithValue(ctx, identity.UserContextKey, su)
        return handler(ctx, req)
    }
}

func setAuthCookies(w http.ResponseWriter, cfg identity.ClientConfig, accessToken, refreshToken string) {
    http.SetCookie(w, &http.Cookie{
        Name:     "access_token",
        Value:    accessToken,
        Path:     "/",
        Domain:   cfg.CookieDomain,
        HttpOnly: cfg.CookieHttpOnly,
        Secure:   cfg.CookieSecure,
        SameSite: http.SameSiteStrictMode,
        MaxAge:   int(cfg.JWTTokenExpiry.Seconds()),
    })
    http.SetCookie(w, &http.Cookie{
        Name:     "refresh_token",
        Value:    refreshToken,
        Path:     "/",
        Domain:   cfg.CookieDomain,
        HttpOnly: cfg.CookieHttpOnly,
        Secure:   cfg.CookieSecure,
        SameSite: http.SameSiteStrictMode,
        MaxAge:   int(cfg.JWTRefreshExpiry.Seconds()),
    })
}

// GetAuthToken extracts the access token from the request.
// Checks cookie first, falls back to Authorization: Bearer header.
func GetAuthToken(r *http.Request) string {
    c, err := r.Cookie("access_token")
    if err == nil {
        return c.Value
    }
    return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}
