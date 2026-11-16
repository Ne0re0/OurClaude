package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"codex-proxy/internal/crypto"
	"codex-proxy/internal/database"

	"gorm.io/gorm"
)

const DefaultClientID = "app_EMoamEEZ73f0CkXaXp7hrann"

type Refresher struct {
	client     *http.Client
	refreshURL string
	clientID   string
	enc        *crypto.Encryptor
	refreshMu  sync.Map
}

func New(refreshURL, clientID string, enc *crypto.Encryptor) *Refresher {
	if clientID == "" {
		clientID = DefaultClientID
	}
	return &Refresher{
		client:     &http.Client{Timeout: 45 * time.Second},
		refreshURL: refreshURL,
		clientID:   clientID,
		enc:        enc,
	}
}

type refreshResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// RefreshToken rotates one ChatGPT OAuth credential set. account must contain
// plaintext tokens; the persisted values remain encrypted at rest.
func (r *Refresher) RefreshToken(db *gorm.DB, account *database.CodexAccount) error {
	if account.OAuthProvider == "siwc" {
		return r.refreshSIWC(db, account)
	}

	body, err := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": account.RefreshToken,
		"client_id":     firstNonEmpty(account.OAuthClientID, r.clientID),
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, refreshEndpoint(account.OAuthIssuer, r.refreshURL), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var result refreshResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return err
	}
	if result.AccessToken == "" {
		return fmt.Errorf("no access token in refresh response")
	}

	refreshToken := firstNonEmpty(result.RefreshToken, account.RefreshToken)
	idToken := firstNonEmpty(result.IDToken, account.IDToken)
	expiresAt := TokenExpiresAt(result.AccessToken)
	if expiresAt.IsZero() && result.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(time.Hour)
	}

	encAccess, err := r.enc.Encrypt(result.AccessToken)
	if err != nil {
		return err
	}
	encRefresh, err := r.enc.Encrypt(refreshToken)
	if err != nil {
		return err
	}
	encID, err := r.enc.Encrypt(idToken)
	if err != nil {
		return err
	}

	accountID := firstNonEmpty(AccountIDFromJWT(result.AccessToken), AccountIDFromJWT(idToken), account.ChatGPTAccountID)
	now := time.Now()
	updates := map[string]interface{}{
		"access_token":        encAccess,
		"refresh_token":       encRefresh,
		"refresh_token_hash":  RefreshTokenHash(refreshToken),
		"id_token":            encID,
		"chat_gpt_account_id": accountID,
		"expires_at":          expiresAt,
		"status":              "active",
		"last_error":          "",
		"last_used_at":        now,
	}
	if err := db.Model(account).Updates(updates).Error; err != nil {
		return err
	}

	account.AccessToken = result.AccessToken
	account.RefreshToken = refreshToken
	account.RefreshTokenHash = RefreshTokenHash(refreshToken)
	account.IDToken = idToken
	account.ChatGPTAccountID = accountID
	account.ExpiresAt = expiresAt
	account.Status = "active"
	account.LastUsedAt = &now
	return nil
}

func (r *Refresher) refreshSIWC(db *gorm.DB, account *database.CodexAccount) error {
	clientID := strings.TrimSpace(account.OAuthClientID)
	if !ValidIssuedClientID(clientID) {
		return fmt.Errorf("SIWC account has no issued OAuth client ID")
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {account.RefreshToken},
		"client_id":     {clientID},
		"resource":      {SIWCResource},
	}
	req, err := http.NewRequest(http.MethodPost, SIWCTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var result SIWCTokenResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return fmt.Errorf("decode SIWC refresh response: %w", err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" {
		return fmt.Errorf("SIWC refresh response did not contain replacement credentials")
	}
	expiresAt := TokenExpiresAt(result.AccessToken)
	if expiresAt.IsZero() && result.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	}
	if expiresAt.IsZero() {
		return fmt.Errorf("SIWC refresh response did not contain an expiry")
	}
	idToken := firstNonEmpty(result.IDToken, account.IDToken)

	encAccess, err := r.enc.Encrypt(result.AccessToken)
	if err != nil {
		return err
	}
	encRefresh, err := r.enc.Encrypt(result.RefreshToken)
	if err != nil {
		return err
	}
	encID, err := r.enc.Encrypt(idToken)
	if err != nil {
		return err
	}
	now := time.Now()
	updates := map[string]interface{}{
		"access_token":       encAccess,
		"refresh_token":      encRefresh,
		"refresh_token_hash": RefreshTokenHash(result.RefreshToken),
		"id_token":           encID,
		"expires_at":         expiresAt,
		"status":             "active",
		"last_error":         "",
		"last_used_at":       now,
	}
	if err := db.Model(account).Updates(updates).Error; err != nil {
		return err
	}

	account.AccessToken = result.AccessToken
	account.RefreshToken = result.RefreshToken
	account.RefreshTokenHash = RefreshTokenHash(result.RefreshToken)
	account.IDToken = idToken
	account.ExpiresAt = expiresAt
	account.Status = "active"
	account.LastUsedAt = &now
	return nil
}

// EnsureValid refreshes a token that expires within five minutes.
func (r *Refresher) EnsureValid(db *gorm.DB, account *database.CodexAccount) error {
	if time.Until(account.ExpiresAt) > 5*time.Minute {
		return nil
	}

	value, _ := r.refreshMu.LoadOrStore(account.ID, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	var stored database.CodexAccount
	if err := db.First(&stored, account.ID).Error; err != nil {
		return err
	}
	if time.Until(stored.ExpiresAt) > 5*time.Minute {
		return r.decryptInto(&stored, account)
	}
	if err := r.decryptInto(&stored, account); err != nil {
		return err
	}
	return r.RefreshToken(db, account)
}

func (r *Refresher) decryptInto(stored, target *database.CodexAccount) error {
	access, err := r.enc.Decrypt(stored.AccessToken)
	if err != nil {
		return err
	}
	refresh, err := r.enc.Decrypt(stored.RefreshToken)
	if err != nil {
		return err
	}
	idToken := ""
	if stored.IDToken != "" {
		idToken, err = r.enc.Decrypt(stored.IDToken)
		if err != nil {
			return err
		}
	}
	*target = *stored
	target.AccessToken = access
	target.RefreshToken = refresh
	target.IDToken = idToken
	return nil
}

func refreshEndpoint(issuer, fallback string) string {
	if strings.TrimSpace(issuer) == "" {
		return fallback
	}
	return strings.TrimRight(issuer, "/") + "/oauth/token"
}

func RefreshTokenHash(token string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
}

func TokenExpiresAt(token string) time.Time {
	claims := jwtClaims(token)
	if exp, ok := numberClaim(claims, "exp"); ok {
		return time.Unix(exp, 0)
	}
	return time.Time{}
}

func AccountIDFromJWT(token string) string {
	claims := jwtClaims(token)
	if value, ok := claims["chatgpt_account_id"].(string); ok {
		return value
	}
	if auth, ok := claims["https://api.openai.com/auth"].(map[string]interface{}); ok {
		if value, ok := auth["chatgpt_account_id"].(string); ok {
			return value
		}
	}
	return ""
}

func jwtClaims(token string) map[string]interface{} {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]interface{}
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	return claims
}

func numberClaim(claims map[string]interface{}, key string) (int64, bool) {
	if claims == nil {
		return 0, false
	}
	value, ok := claims[key].(float64)
	return int64(value), ok
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
