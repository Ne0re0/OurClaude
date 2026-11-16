package oauth

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testKID = "test-key"

// newTestJWKS serves key as OpenAI's JWKS endpoint would.
func newTestJWKS(t *testing.T) (*rsa.PrivateKey, *httptest.Server) {
	t.Helper()
	key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		eBytes := big.NewInt(int64(key.PublicKey.E)).Bytes()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{{
				"kty": "RSA",
				"kid": testKID,
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	}))
	t.Cleanup(server.Close)
	return key, server
}

func testIDToken(t *testing.T, key *rsa.PrivateKey, clientID string, extra jwt.MapClaims) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   SIWCIssuer,
		"aud":   []string{clientID},
		"sub":   "subject-123",
		"email": "person@example.com",
		"name":  "Person",
		"nonce": "expected-nonce",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	for name, value := range extra {
		claims[name] = value
	}
	return signedTestJWT(t, key, testKID, claims)
}

func TestVerifySIWCCredentials(t *testing.T) {
	key, server := newTestJWKS(t)
	now := time.Now()
	clientID := "oaiapp_test-client"
	accessToken := signedTestJWT(t, key, testKID, jwt.MapClaims{
		"iss":       SIWCIssuer,
		"aud":       SIWCResource,
		"client_id": clientID,
		"scope":     "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct",
		"iat":       now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	})
	tokens := SIWCTokenResponse{
		IDToken:      testIDToken(t, key, clientID, nil),
		AccessToken:  accessToken,
		RefreshToken: "refresh-token",
		ExpiresIn:    3600,
	}

	identity, err := verifySIWCCredentials(context.Background(), server.Client(), tokens, clientID, "expected-nonce", server.URL)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if identity.Subject != "subject-123" || identity.Email != "person@example.com" {
		t.Fatalf("unexpected identity: %#v", identity)
	}

	if _, err := verifySIWCCredentials(context.Background(), server.Client(), tokens, clientID, "wrong-nonce", server.URL); err == nil {
		t.Fatal("expected nonce mismatch to fail")
	}
}

// OpenAI's token endpoint returns earliest_refresh_at as Unix seconds. A fixed
// string field made every successful code exchange fail to decode.
func TestSIWCTokenResponseDecodesEarliestRefreshAt(t *testing.T) {
	for _, value := range []string{`1790034332`, `"2026-11-16T12:00:00Z"`} {
		body := `{"access_token":"a","refresh_token":"r","id_token":"i","token_type":"Bearer","expires_in":3600,` +
			`"scope":"openid chatgpt.tokens.use.direct","earliest_refresh_at":` + value + `}`
		var tokens SIWCTokenResponse
		if err := json.Unmarshal([]byte(body), &tokens); err != nil {
			t.Fatalf("decode earliest_refresh_at=%s: %v", value, err)
		}

		// The CLI re-encodes the response for the server, which decodes it again.
		forwarded, err := json.Marshal(map[string]interface{}{"client_id": "oaiapp_x", "tokens": tokens})
		if err != nil {
			t.Fatal(err)
		}
		var received struct {
			Tokens SIWCTokenResponse `json:"tokens"`
		}
		if err := json.Unmarshal(forwarded, &received); err != nil {
			t.Fatalf("server decode earliest_refresh_at=%s: %v", value, err)
		}
		if string(received.Tokens.EarliestRefreshAt) != value || received.Tokens.AccessToken != "a" {
			t.Fatalf("round trip changed the response: %#v", received.Tokens)
		}
	}
}

// OpenAI documents the token response's scope as the granted permissions and
// access tokens as opaque, so neither a non-JWT access token nor a client ID
// without the usual prefix may block sign-in.
func TestVerifySIWCCredentialsUsesTokenResponseScopes(t *testing.T) {
	key, server := newTestJWKS(t)
	clientID := "agentclient_123"
	tokens := SIWCTokenResponse{
		IDToken:      testIDToken(t, key, clientID, nil),
		AccessToken:  "opaque-access-token",
		RefreshToken: "refresh-token",
		ExpiresIn:    3600,
		Scope:        "chatgpt.tokens.use.direct email offline_access openid profile resource.invoke",
	}
	identity, err := verifySIWCCredentials(context.Background(), server.Client(), tokens, clientID, "expected-nonce", server.URL)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if until := time.Until(identity.ExpiresAt); until < 59*time.Minute || until > time.Hour {
		t.Fatalf("expiry not derived from expires_in: %v", identity.ExpiresAt)
	}

	withoutPlanUsage := tokens
	withoutPlanUsage.Scope = "openid profile email offline_access"
	if _, err := verifySIWCCredentials(context.Background(), server.Client(), withoutPlanUsage, clientID, "expected-nonce", server.URL); err == nil || !strings.Contains(err.Error(), SIWCRequiredScope) {
		t.Fatalf("expected missing plan-usage scope to fail, got %v", err)
	}
}

func TestVerifySIWCCredentialsRejectsWrongClient(t *testing.T) {
	key, server := newTestJWKS(t)
	clientID := "oaiapp_test-client"
	base := SIWCTokenResponse{
		AccessToken:  "opaque-access-token",
		RefreshToken: "refresh-token",
		ExpiresIn:    3600,
		Scope:        SIWCRegistrationScope,
	}

	cases := map[string]struct {
		clientID string
		idToken  string
	}{
		"registration placeholder": {SIWCDynamicClientID, testIDToken(t, key, SIWCDynamicClientID, nil)},
		"audience mismatch":        {clientID, testIDToken(t, key, "oaiapp_other", nil)},
		"authorized party":         {clientID, testIDToken(t, key, clientID, jwt.MapClaims{"azp": "oaiapp_other"})},
		"multiple audiences":       {clientID, testIDToken(t, key, clientID, jwt.MapClaims{"aud": []string{clientID, "oaiapp_other"}})},
	}
	for name, tc := range cases {
		tokens := base
		tokens.IDToken = tc.idToken
		if _, err := verifySIWCCredentials(context.Background(), server.Client(), tokens, tc.clientID, "expected-nonce", server.URL); err == nil {
			t.Errorf("%s: expected verification to fail", name)
		}
	}
}

func TestValidIssuedClientID(t *testing.T) {
	for id, want := range map[string]bool{
		"oaiapp_EHBV7pzdMtehZ7j6Ypgyje-F": true,
		"agentclient_123":                 true,
		SIWCDynamicClientID:               false,
		"":                                false,
		"oaiapp_bad id":                   false,
		"oaiapp_<script>":                 false,
		strings.Repeat("a", 201):          false,
	} {
		if got := ValidIssuedClientID(id); got != want {
			t.Errorf("ValidIssuedClientID(%q) = %v, want %v", id, got, want)
		}
	}
}

func signedTestJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
