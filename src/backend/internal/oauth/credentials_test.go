package oauth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func fakeJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func TestParseAndBuildAuthFile(t *testing.T) {
	expires := time.Now().Add(time.Hour).Unix()
	access := fakeJWT(t, map[string]interface{}{
		"exp": expires,
		"https://api.openai.com/auth": map[string]interface{}{
			"chatgpt_account_id": "acct-test",
		},
	})
	raw, err := json.Marshal(AuthFile{
		AuthMode: "chatgpt",
		Tokens: &TokenData{
			IDToken:      "id-token",
			AccessToken:  access,
			RefreshToken: "refresh-token",
			LoginOwnerID: "owner-test",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	creds, err := ParseAuthJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccountID != "acct-test" || creds.LoginOwnerID != "owner-test" {
		t.Fatalf("unexpected credentials: %#v", creds)
	}
	if creds.Issuer != "https://auth.openai.com" || creds.ClientID != DefaultClientID {
		t.Fatalf("defaults not applied: %#v", creds)
	}

	exported := BuildAuthFile(creds)
	if exported.AuthMode != "chatgpt" || exported.Tokens == nil || exported.Tokens.AccessToken != access {
		t.Fatalf("unexpected auth export: %#v", exported)
	}
	if exported.OpenAIAPIKey != nil {
		t.Fatalf("OPENAI_API_KEY should be null for ChatGPT auth")
	}
}
