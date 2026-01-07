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
    tenantSlug string
}

func NewClient(addr, tenantSlug string) (*Client, error) {
    conn, err := grpc.NewClient(addr,
        grpc.WithTransportCredentials(insecure.NewCredentials()),
    )
    if err != nil {
        return nil, fmt.Errorf("could not connect to identity platform: %w", err)
    }
    return &Client{
        grpcClient: pb.NewIdentityServiceClient(conn),
        conn:       conn,
        tenantSlug: tenantSlug,
    }, nil
}

// AuthenticateWithProvider is what the frontend calls
// after getting a token from the external auth provider.
func (c *Client) AuthenticateWithProvider(ctx context.Context, providerToken string) (*pb.AuthenticateResponse, error) {
    return c.grpcClient.Authenticate(ctx, &pb.AuthenticateRequest{
        Credentials: &pb.AuthenticateRequest_ProviderToken{
            ProviderToken: providerToken,
        },
        TenantSlug: c.tenantSlug,
    })
}

func (c *Client) AuthenticateWithCredentials(ctx context.Context, email, password string) (*pb.AuthenticateResponse, error) {
    return c.grpcClient.Authenticate(ctx, &pb.AuthenticateRequest{
        Credentials: &pb.AuthenticateRequest_Credential{
            Credential: &pb.UserCredentials{
                Email:    email,
                Password: password,
            },
        },
        TenantSlug: c.tenantSlug,
    })
}

// ValidateSession is used by the middleware to check
// if the JWT from the request is valid.
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
