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

// CountUnusedBackupCodes reports how many recovery codes the signed-in user
// still holds, so a client can warn a user who has burned through them.
func (c *Client) CountUnusedBackupCodes(ctx context.Context) (int, error) {
	resp, err := c.svcAuth.CountUnusedBackupCodes(ctx, &pb.CountUnusedBackupCodesRequest{})
	if err != nil {
		return 0, err
	}
	return int(resp.GetBackupCodesLeft()), nil
}

// ReissueBackupCodes hands the signed-in user a fresh batch of recovery codes
// and destroys the old ones. It is gated on the current password: it is the one
// call that destroys working credentials, so a stolen session must not be able
// to rotate the codes out from under its owner.
func (c *Client) ReissueBackupCodes(ctx context.Context, currentPassword string) ([]string, error) {
	resp, err := c.svcAuth.ReissueBackupCodes(ctx, &pb.ReissueBackupCodesRequest{
		CurrentPassword: currentPassword,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetBackupCodes(), nil
}

// BeginTOTPEnroll starts TOTP enrollment. The authenticator entry is labelled
// with the signed-in user's email by the service; a custom label is typed
// directly into the authenticator app, so there is no account parameter.
func (c *Client) BeginTOTPEnroll(ctx context.Context) (*pb.BeginTOTPEnrollResponse, error) {
	return c.svcAuth.BeginTOTPEnroll(ctx, &pb.BeginTOTPEnrollRequest{})
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

// BeginWebAuthnEnroll starts passkey enrollment. The credential's user name
// comes from the signed-in user's email; only the cosmetic display name is
// passed through (empty falls back to the user's display name).
func (c *Client) BeginWebAuthnEnroll(ctx context.Context, displayName string) (*pb.BeginWebAuthnEnrollResponse, error) {
	return c.svcAuth.BeginWebAuthnEnroll(ctx, &pb.BeginWebAuthnEnrollRequest{
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
