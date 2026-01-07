package middleware

import (
    "context"
    "net/http"
    "strings"

    "github.com/kodeart/go-problem/v2"

    "github.com/kodeart/identity-module/sdk/go"
)

// IdentityAuth is the core part of the identification of
// any user against the configured external service provider.
// This middleware is what is imported in all future projects
// to resolve the user identity.
func IdentityAuth(client *identity.Client) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
                problem.New().
                    WithDetail("Missing auth header").
                    WithTitle("Identity Not Authorized").
                    WithStatus(http.StatusUnauthorized).
                    WithInstance(r.URL.String()).
                    WithType("https://...").
                    WithExtension("error", "Provide the authorization header").
                    JSON(w)

                return
            }
            token := strings.TrimPrefix(authHeader, "Bearer ")
            user, err := client.ValidateSession(r.Context(), token)
            if err != nil {
                problem.New().
                    WithDetail("Invalid Token").
                    WithTitle("Identity Not Authorized").
                    WithStatus(http.StatusUnauthorized).
                    WithInstance(r.URL.String()).
                    WithType("https://...").
                    WithExtension("error", err.Error()).
                    JSON(w)

                return
            }

            ctx := context.WithValue(r.Context(), identity.UserContextKey, user)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
