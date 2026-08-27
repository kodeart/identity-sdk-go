package identity

import (
	"context"

	pb "github.com/kodeart/identity-sdk-go/proto/identity/v1"
)

func (c *Client) CreateRole(ctx context.Context, name, description, parentRole string, permissions []string) (*pb.Role, error) {
	return c.svcRole.Create(ctx, &pb.CreateRoleRequest{
		Name:        name,
		Description: description,
		ParentRole:  parentRole,
		Permissions: permissions,
	})
}

func (c *Client) GetRole(ctx context.Context, roleId string) (*pb.Role, error) {
	return c.svcRole.Get(ctx, &pb.GetRoleRequest{RoleId: roleId})
}

func (c *Client) ListRoles(ctx context.Context) ([]*pb.Role, error) {
	resp, err := c.svcRole.List(ctx, &pb.ListRolesRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetRoles(), nil
}

func (c *Client) DeleteRole(ctx context.Context, roleId string) error {
	_, err := c.svcRole.Delete(ctx, &pb.DeleteRoleRequest{RoleId: roleId})
	return err
}

func (c *Client) SetRolePermissions(ctx context.Context, roleId string, permissions []string) (*pb.Role, error) {
	return c.svcRole.SetPermissions(ctx, &pb.SetRolePermissionsRequest{
		RoleId:      roleId,
		Permissions: permissions,
	})
}

func (c *Client) SetRoleParent(ctx context.Context, roleId, parentRole string) (*pb.Role, error) {
	return c.svcRole.SetParent(ctx, &pb.SetRoleParentRequest{
		RoleId:     roleId,
		ParentRole: parentRole,
	})
}
