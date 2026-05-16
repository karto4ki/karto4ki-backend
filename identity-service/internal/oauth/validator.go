package oauth

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var oidcHTTPClient = &http.Client{Timeout: 10 * time.Second}

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

type providerCache struct {
	mu       sync.Mutex
	provider *oidc.Provider
}

func (c *providerCache) get(ctx context.Context, issuer string) (*oidc.Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return c.provider, nil
	}
	fetchCtx := oidc.ClientContext(ctx, oidcHTTPClient)
	p, err := oidc.NewProvider(fetchCtx, issuer)
	if err != nil {
		return nil, err
	}
	c.provider = p
	return p, nil
}

var (
	googleProviderCache = &providerCache{}
	appleProviderCache  = &providerCache{}
)

func VerifyGoogleIDToken(ctx context.Context, idToken, clientID string) (*GoogleTokenInfo, error) {
	ctx = oidc.ClientContext(ctx, oidcHTTPClient)
	provider, err := googleProviderCache.get(ctx, "https://accounts.google.com")
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
	IsPrivateEmail bool   `json:"is_private_email"`
}

func VerifyAppleIDToken(ctx context.Context, idToken, clientID string) (*AppleTokenClaims, error) {
	ctx = oidc.ClientContext(ctx, oidcHTTPClient)
	provider, err := appleProviderCache.get(ctx, "https://appleid.apple.com")
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
