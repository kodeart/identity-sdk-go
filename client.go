package identity

import (
    "context"
    "fmt"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"

    pb "github.com/kodeart/identity-module/sdk/go/proto/v1"
)

type Client struct {
    grpcClient pb.IdentityServiceClient
    conn       *grpc.ClientConn
}

func NewClient(addr string) (*Client, error) {
    conn, err := grpc.NewClient(addr,
        grpc.WithTransportCredentials(insecure.NewCredentials()),
    )
    if err != nil {
        return nil, err //fmt.Errorf("could not connect to identity platform: %w", err)
    }
    return &Client{
        grpcClient: pb.NewIdentityServiceClient(conn),
        conn:       conn,
    }, nil
}

// AuthenticateWithProvider is what the frontend calls
// after getting a token from the external auth provider.
func (c *Client) AuthenticateWithProvider(ctx context.Context, tenantSlug, providerToken string) (*pb.AuthenticateResponse, error) {
    return c.grpcClient.Authenticate(ctx, &pb.AuthenticateRequest{
        TenantSlug: tenantSlug,
        Credentials: &pb.AuthenticateRequest_ProviderToken{
            ProviderToken: providerToken,
        },
    })
}

func (c *Client) AuthenticateWithCredentials(ctx context.Context, tenantSlug, email, password string) (*pb.AuthenticateResponse, error) {
    return c.grpcClient.Authenticate(ctx, &pb.AuthenticateRequest{
        TenantSlug: tenantSlug,
        Credentials: &pb.AuthenticateRequest_Credential{
            Credential: &pb.UserCredentials{
                Email:    email,
                Password: password,
            },
        },
    })
}

// ValidateSession is used by the middleware
// to check if the JWT from the request is valid.
func (c *Client) ValidateSession(ctx context.Context, token string) (*pb.User, error) {
    resp, err := c.grpcClient.ValidateSession(ctx, &pb.ValidateSessionRequest{Token: token})
    if err != nil {
        return nil, err
    }
    if !resp.Valid {
        return nil, fmt.Errorf("invalid session")
    }
    return resp.User, nil
}

func (c *Client) Close() error {
    return c.conn.Close()
}
