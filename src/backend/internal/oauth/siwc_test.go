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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifySIWCCredentials(t *testing.T) {
	key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "test-key"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		eBytes := big.NewInt(int64(key.PublicKey.E)).Bytes()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{{
				"kty": "RSA",
				"kid": kid,
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	}))
	defer server.Close()

	now := time.Now()
	clientID := "oaiapp_test-client"
	idToken := signedTestJWT(t, key, kid, jwt.MapClaims{
		"iss":   SIWCIssuer,
		"aud":   []string{clientID},
		"sub":   "subject-123",
		"email": "person@example.com",
		"name":  "Person",
		"nonce": "expected-nonce",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	accessToken := signedTestJWT(t, key, kid, jwt.MapClaims{
		"iss":       SIWCIssuer,
		"aud":       SIWCResource,
		"client_id": clientID,
		"scope":     "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct",
		"iat":       now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	})
	tokens := SIWCTokenResponse{
		IDToken:      idToken,
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
