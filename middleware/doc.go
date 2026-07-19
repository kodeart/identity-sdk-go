// Package middleware provides auth middleware for consuming the identity service.
//
// # Verification strategies
//
// Two ways to verify a JWT token:
//
//   - Local verify: identity.VerifyToken(token, secretKey, issuer) — runs in your
//     process, checks HMAC signature + expiry using the secret key you already have.
//     Zero network calls. Fast.
//
//   - Remote verify: client.ValidateSession(ctx, token) — gRPC call to the identity
//     service, which does the same HMAC check plus DB lookup (session table, blacklist).
//     Slow. Only needed when you can't trust the local secret key.
//
// Both AuthHTTP and AuthGRPC use local verify — you have the secret key, no reason
// to call home for every request. Refresh is the only time we call the identity
// service (via gRPC).
//
// # Middleware
//
// Three middlewares for three scenarios:
//
//  1. AuthHTTP(client) — for REST apps consuming identity as a separate service.
//     Local verify fast-path, gRPC refresh on expiry, sets new cookies.
//
//  2. AuthGRPC(client) — for gRPC servers that need to authenticate incoming gRPC
//     calls via identity tokens. Local verify only, no refresh (gRPC has no cookie
//     mechanism).
//
//  3. server.AuthHTTP(authSvc) — for apps that embed identity as a library (import pkg/
//     directly). Calls IAuthService.ValidateSession and RefreshToken directly — same
//     process, no gRPC.
//
// All three put *SessionUser in context. Access via identity.GetUser(ctx) (SDK)
// or server.GetUser(ctx) (embedded).
package middleware
