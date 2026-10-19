package identity

import (
	"context"

	pb "github.com/kodeart/identity-sdk-go/proto/identity/v1"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func (c *Client) GetUser(ctx context.Context, userId string) (*pb.User, error) {
	resp, err := c.svcUser.Get(ctx, &pb.GetUserRequest{UserId: userId})
	if err != nil {
		return nil, err
	}
	return resp.GetUser(), nil
}

func (c *Client) ListUsers(ctx context.Context, size int32, page, sort string) ([]*pb.User, string, error) {
	resp, err := c.svcUser.List(ctx, &pb.ListUsersRequest{
		Size: size,
		Page: page,
		Sort: sort,
	})
	if err != nil {
		return nil, "", err
	}
	return resp.GetUsers(), resp.GetNext(), nil
}

func (c *Client) CreateUser(ctx context.Context, email, password, displayName string, roles, permissions, exclusions []string, externalId string) (*pb.User, error) {
	resp, err := c.svcUser.Create(ctx, &pb.CreateUserRequest{
		Credentials: &pb.UserCredentials{
			Email:    email,
			Password: password,
		},
		DisplayName: displayName,
		Roles:       roles,
		Permissions: permissions,
		Exclusions:  exclusions,
		ExternalId:  externalId,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetUser(), nil
}

// GetUserPermissions resolves the user's effective permission set: role
// permissions (incl. parent-chain inheritance) plus per-user grants, minus
// per-user exclusions.
func (c *Client) GetUserPermissions(ctx context.Context, userId string) ([]string, error) {
	resp, err := c.svcUser.GetUserPermissions(ctx, &pb.GetUserRequest{UserId: userId})
	if err != nil {
		return nil, err
	}
	return resp.GetPermissions(), nil
}

func (c *Client) UpdateUser(ctx context.Context, userId string, user *pb.User, updateMask []string) (*pb.User, error) {
	resp, err := c.svcUser.Update(ctx, &pb.UpdateUserRequest{
		UserId:     userId,
		User:       user,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: updateMask},
	})
	if err != nil {
		return nil, err
	}
	return resp.GetUser(), nil
}

func (c *Client) DeleteUser(ctx context.Context, userId string) error {
	_, err := c.svcUser.Delete(ctx, &pb.DeleteUserRequest{UserId: userId})
	return err
}

func (c *Client) ChangePassword(ctx context.Context, userId, currentPassword, newPassword string) error {
	_, err := c.svcUser.ChangePassword(ctx, &pb.ChangePasswordRequest{
		UserId:          userId,
		CurrentPassword: currentPassword,
		NewPassword:     newPassword,
	})
	return err
}

func (c *Client) ChangeEmail(ctx context.Context, userId, currentPassword, newEmail string) (*pb.ChangeEmailResponse, error) {
	return c.svcUser.ChangeEmail(ctx, &pb.ChangeEmailRequest{
		UserId:          userId,
		CurrentPassword: currentPassword,
		NewEmail:        newEmail,
	})
}

func (c *Client) InitiatePasswordReset(ctx context.Context, email string) (*pb.PasswordResetResponse, error) {
	return c.svcUser.InitiatePasswordReset(ctx, &pb.PasswordResetRequest{Email: email})
}

// AdminResetFactors clears the target's MFA factors and recovery codes and
// revokes their sessions. The caller must hold the user.reset permission; the
// target is a factor id or a user id.
func (c *Client) AdminResetFactors(ctx context.Context, mfaId string) error {
	_, err := c.svcUser.AdminResetFactors(ctx, &pb.AdminResetFactorsRequest{MfaId: mfaId})
	return err
}
