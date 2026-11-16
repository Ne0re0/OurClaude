package oauth

import (
	"encoding/json"
	"fmt"
	"time"
)

// AuthFile is the subset of $CODEX_HOME/auth.json needed to share and refresh
// a ChatGPT-backed Codex login. Unknown fields are intentionally ignored on
// import and preserved by the OurCodex client when it syncs local credentials.
type AuthFile struct {
	AuthMode     string     `json:"auth_mode,omitempty"`
	OpenAIAPIKey *string    `json:"OPENAI_API_KEY"`
	Tokens       *TokenData `json:"tokens,omitempty"`
	LastRefresh  string     `json:"last_refresh,omitempty"`
}

type TokenData struct {
	IDToken         string           `json:"id_token"`
	AccessToken     string           `json:"access_token"`
	RefreshToken    string           `json:"refresh_token"`
	OAuthProvenance *OAuthProvenance `json:"oauth_provenance,omitempty"`
	LoginOwnerID    string           `json:"login_owner_id,omitempty"`
	AccountID       string           `json:"account_id,omitempty"`
}

type OAuthProvenance struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
}

type CredentialSet struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	AccountID    string
	Issuer       string
	ClientID     string
	ExpiresAt    time.Time
	LoginOwnerID string
}

func ParseAuthJSON(data []byte) (CredentialSet, error) {
	var auth AuthFile
	if err := json.Unmarshal(data, &auth); err != nil {
		return CredentialSet{}, fmt.Errorf("invalid Codex auth.json: %w", err)
	}
	if auth.Tokens == nil {
		return CredentialSet{}, fmt.Errorf("auth.json must contain tokens")
	}
	tokens := auth.Tokens
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		return CredentialSet{}, fmt.Errorf("auth.json must contain tokens.access_token and tokens.refresh_token")
	}

	result := CredentialSet{
		IDToken:      tokens.IDToken,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		AccountID:    tokens.AccountID,
		ExpiresAt:    TokenExpiresAt(tokens.AccessToken),
		LoginOwnerID: tokens.LoginOwnerID,
	}
	if result.AccountID == "" {
		result.AccountID = AccountIDFromJWT(tokens.AccessToken)
	}
	if result.AccountID == "" {
		result.AccountID = AccountIDFromJWT(tokens.IDToken)
	}
	if tokens.OAuthProvenance != nil {
		result.Issuer = tokens.OAuthProvenance.Issuer
		result.ClientID = tokens.OAuthProvenance.ClientID
	}
	if result.Issuer == "" {
		result.Issuer = "https://auth.openai.com"
	}
	if result.ClientID == "" {
		result.ClientID = DefaultClientID
	}
	if result.ExpiresAt.IsZero() {
		result.ExpiresAt = time.Now().Add(time.Hour)
	}
	if result.AccountID == "" {
		return CredentialSet{}, fmt.Errorf("auth.json does not identify a ChatGPT account")
	}
	return result, nil
}

func BuildAuthFile(creds CredentialSet) AuthFile {
	var apiKey *string
	issuer := firstNonEmpty(creds.Issuer, "https://auth.openai.com")
	clientID := firstNonEmpty(creds.ClientID, DefaultClientID)
	return AuthFile{
		AuthMode:     "chatgpt",
		OpenAIAPIKey: apiKey,
		Tokens: &TokenData{
			IDToken:      creds.IDToken,
			AccessToken:  creds.AccessToken,
			RefreshToken: creds.RefreshToken,
			OAuthProvenance: &OAuthProvenance{
				Issuer:   issuer,
				ClientID: clientID,
			},
			LoginOwnerID: creds.LoginOwnerID,
			AccountID:    creds.AccountID,
		},
		LastRefresh: time.Now().UTC().Format(time.RFC3339Nano),
	}
}
