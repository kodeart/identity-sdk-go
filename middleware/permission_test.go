package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	identity "github.com/kodeart/identity-sdk-go"
	pb "github.com/kodeart/identity-sdk-go/proto/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func contextUser(su *pb.SessionUser) context.Context {
	return context.WithValue(context.Background(), identity.UserContextKey, su)
}

func TestRequirePermissionHTTP(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	okHandler := RequirePermission("doc.view")(http.HandlerFunc(ok))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	okHandler.ServeHTTP(rec, req.WithContext(context.Background()))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no user: got %d, want 401", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	su := &pb.SessionUser{Id: "u1", Permissions: []string{"doc.list"}}
	okHandler.ServeHTTP(rec, req.WithContext(contextUser(su)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no perm: got %d, want 403", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	su = &pb.SessionUser{Id: "u1", Permissions: []string{"doc.*"}}
	okHandler.ServeHTTP(rec, req.WithContext(contextUser(su)))
	if rec.Code != http.StatusOK {
		t.Fatalf("has perm: got %d, want 200", rec.Code)
	}
}

func TestRequirePermissionGRPC(t *testing.T) {
	interceptor := RequirePermissionGRPC("doc.view")
	_, err := interceptor(context.Background(), nil, nil, func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing user: got %v, want %v", status.Code(err), codes.Unauthenticated)
	}
}
