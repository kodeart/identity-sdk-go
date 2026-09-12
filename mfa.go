package identity

import (
	"context"

	pb "github.com/kodeart/identity-sdk-go/proto/identity/v1"
)

func (c *Client) BeginMfaSignIn(ctx context.Context, mfaTicket string) (*pb.BeginMfaSignInResponse, error) {
	return c.svcAuth.BeginMfaSignIn(ctx, &pb.BeginMfaSignInRequest{MfaTicket: mfaTicket})
}

func (c *Client) CompleteMfaSignIn(ctx context.Context, req *pb.CompleteMfaSignInRequest) (*pb.SignInResponse, error) {
	return c.svcAuth.CompleteMfaSignIn(ctx, req)
}

func (c *Client) ListMfaFactors(ctx context.Context) ([]*pb.MfaFactor, error) {
	resp, err := c.svcAuth.ListMfaFactors(ctx, &pb.ListMfaFactorsRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetFactors(), nil
}

func (c *Client) BeginTOTPEnroll(ctx context.Context, account string) (*pb.BeginTOTPEnrollResponse, error) {
	return c.svcAuth.BeginTOTPEnroll(ctx, &pb.BeginTOTPEnrollRequest{Account: account})
}

func (c *Client) CompleteTOTPEnroll(ctx context.Context, currentPassword, pendingID, code string) ([]string, error) {
	resp, err := c.svcAuth.CompleteTOTPEnroll(ctx, &pb.CompleteTOTPEnrollRequest{
		CurrentPassword: currentPassword,
		PendingId:       pendingID,
		Code:            code,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetBackupCodes(), nil
}

func (c *Client) BeginWebAuthnEnroll(ctx context.Context, account, displayName string) (*pb.BeginWebAuthnEnrollResponse, error) {
	return c.svcAuth.BeginWebAuthnEnroll(ctx, &pb.BeginWebAuthnEnrollRequest{
		Account:     account,
		DisplayName: displayName,
	})
}

func (c *Client) CompleteWebAuthnEnroll(ctx context.Context, currentPassword, challengeID, response string) ([]string, error) {
	resp, err := c.svcAuth.CompleteWebAuthnEnroll(ctx, &pb.CompleteWebAuthnEnrollRequest{
		CurrentPassword: currentPassword,
		ChallengeId:     challengeID,
		Response:        response,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetBackupCodes(), nil
}

func (c *Client) RemoveMfaFactor(ctx context.Context, factorType pb.MfaFactorType, credentialID, currentPassword string) error {
	_, err := c.svcAuth.RemoveMfaFactor(ctx, &pb.RemoveMfaFactorRequest{
		Type:            factorType,
		CredentialId:    credentialID,
		CurrentPassword: currentPassword,
	})
	return err
}
