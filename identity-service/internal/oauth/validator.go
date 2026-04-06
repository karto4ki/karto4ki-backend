package oauth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

type GoogleTokenInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
}

var (
	VerifyGoogleIDTokenFunc = VerifyGoogleIDToken
	VerifyAppleIDTokenFunc  = VerifyAppleIDToken
)

func VerifyGoogleIDToken(ctx context.Context, idToken, clientID string) (*GoogleTokenInfo, error) {
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, fmt.Errorf("failed to create Google OIDC provider: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	idTokenObj, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify Google token: %w", err)
	}

	var claims GoogleTokenInfo
	if err := idTokenObj.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse Google claims: %w", err)
	}

	if !claims.EmailVerified {
		return nil, fmt.Errorf("email not verified by Google")
	}

	return &claims, nil
}

type AppleTokenClaims struct {
	Sub            string `json:"sub"`
	Email          string `json:"email"`
	EmailVerified  string `json:"email_verified"`
	IsPrivateEmail bool   `json:"is_private_email"`
}

func VerifyAppleIDToken(ctx context.Context, idToken, clientID string) (*AppleTokenClaims, error) {
	provider, err := oidc.NewProvider(ctx, "https://appleid.apple.com")
	if err != nil {
		return nil, fmt.Errorf("failed to create Apple OIDC provider: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	idTokenObj, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify Apple token: %w", err)
	}

	var claims AppleTokenClaims
	if err := idTokenObj.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse Apple claims: %w", err)
	}

	if claims.Email == "" {
		return nil, fmt.Errorf("email not provided by Apple")
	}

	return &claims, nil
}
