package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	SIWCIssuer            = "https://auth.openai.com"
	SIWCAuthorizeURL      = "https://auth.openai.com/api/accounts/authorize"
	SIWCTokenURL          = "https://auth.openai.com/api/accounts/oauth/token"
	SIWCJWKSURL           = "https://auth.openai.com/.well-known/jwks.json"
	SIWCResource          = "https://api.openai.com/v1"
	SIWCDynamicClientID   = "dynamic_agent_client"
	SIWCRequiredScope     = "chatgpt.tokens.use.direct"
	SIWCRegistrationScope = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
)

type SIWCTokenResponse struct {
	AccessToken       string `json:"access_token"`
	RefreshToken      string `json:"refresh_token"`
	IDToken           string `json:"id_token"`
	TokenType         string `json:"token_type"`
	ExpiresIn         int    `json:"expires_in"`
	Scope             string `json:"scope"`
	EarliestRefreshAt string `json:"earliest_refresh_at,omitempty"`
}

type SIWCIdentity struct {
	Subject   string
	Email     string
	Name      string
	ExpiresAt time.Time
	Scopes    []string
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// VerifySIWCCredentials verifies both tokens OpenAI returns for the
// open-source Sign in with ChatGPT flow. expectedNonce is required by the
// local CLI; the receiving server passes an empty nonce after the CLI has
// already checked it, while still re-verifying signature, issuer, audience,
// expiry, client binding, and granted scope.
func VerifySIWCCredentials(ctx context.Context, client *http.Client, tokens SIWCTokenResponse, clientID, expectedNonce string) (SIWCIdentity, error) {
	return verifySIWCCredentials(ctx, client, tokens, clientID, expectedNonce, SIWCJWKSURL)
}

func verifySIWCCredentials(ctx context.Context, client *http.Client, tokens SIWCTokenResponse, clientID, expectedNonce, jwksURL string) (SIWCIdentity, error) {
	if tokens.IDToken == "" || tokens.AccessToken == "" || tokens.RefreshToken == "" {
		return SIWCIdentity{}, fmt.Errorf("OpenAI token response is incomplete")
	}
	if !strings.HasPrefix(clientID, "oaiapp_") {
		return SIWCIdentity{}, fmt.Errorf("OpenAI did not issue a valid client ID")
	}

	keys, err := fetchJWKS(ctx, client, jwksURL)
	if err != nil {
		return SIWCIdentity{}, err
	}

	idClaims, err := verifyJWT(tokens.IDToken, clientID, keys)
	if err != nil {
		return SIWCIdentity{}, fmt.Errorf("invalid OpenAI ID token: %w", err)
	}
	if expectedNonce != "" {
		nonce, _ := idClaims["nonce"].(string)
		if nonce != expectedNonce {
			return SIWCIdentity{}, fmt.Errorf("OpenAI ID token nonce did not match")
		}
	}
	subject, _ := idClaims["sub"].(string)
	if subject == "" {
		return SIWCIdentity{}, fmt.Errorf("OpenAI ID token did not contain a subject")
	}

	accessClaims, err := verifyJWT(tokens.AccessToken, SIWCResource, keys)
	if err != nil {
		return SIWCIdentity{}, fmt.Errorf("invalid OpenAI access token: %w", err)
	}
	boundClientID, _ := accessClaims["client_id"].(string)
	if boundClientID != clientID {
		return SIWCIdentity{}, fmt.Errorf("OpenAI access token is bound to a different client")
	}

	scopeText, _ := accessClaims["scope"].(string)
	scopes := strings.Fields(scopeText)
	if !containsScope(scopes, SIWCRequiredScope) || !containsScope(scopes, "resource.invoke") || !containsScope(scopes, "offline_access") {
		return SIWCIdentity{}, fmt.Errorf("ChatGPT plan usage permission was not granted")
	}

	expiry := TokenExpiresAt(tokens.AccessToken)
	if expiry.IsZero() && tokens.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	}
	if expiry.IsZero() {
		return SIWCIdentity{}, fmt.Errorf("OpenAI access token did not contain an expiry")
	}

	email, _ := idClaims["email"].(string)
	name, _ := idClaims["name"].(string)
	return SIWCIdentity{
		Subject:   subject,
		Email:     email,
		Name:      name,
		ExpiresAt: expiry,
		Scopes:    scopes,
	}, nil
}

func fetchJWKS(ctx context.Context, client *http.Client, jwksURL string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch OpenAI signing keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch OpenAI signing keys: HTTP %d", resp.StatusCode)
	}

	var set jwkSet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("decode OpenAI signing keys: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, item := range set.Keys {
		if item.Kty != "RSA" || item.Kid == "" || item.N == "" || item.E == "" {
			continue
		}
		key, err := rsaKey(item.N, item.E)
		if err != nil {
			continue
		}
		keys[item.Kid] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("OpenAI signing-key set contained no usable RSA keys")
	}
	return keys, nil
}

func verifyJWT(raw, audience string, keys map[string]*rsa.PublicKey) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		key := keys[kid]
		if key == nil {
			return nil, fmt.Errorf("unknown signing key")
		}
		return key, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(SIWCIssuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(5*time.Second),
	)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}
	return claims, nil
}

func rsaKey(modulus, exponent string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(exponent)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e <= 0 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func containsScope(scopes []string, wanted string) bool {
	for _, scope := range scopes {
		if scope == wanted {
			return true
		}
	}
	return false
}
