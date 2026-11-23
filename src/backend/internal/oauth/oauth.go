package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"claude-proxy/internal/crypto"
	"claude-proxy/internal/database"

	"gorm.io/gorm"
)

// claudeClientID is the public OAuth client ID used by the Claude CLI.
const claudeClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

const (
	// requestRefreshWindow: on the request path, refresh if the token expires within this window.
	requestRefreshWindow = 5 * time.Minute
	// backgroundRefreshWindow: the background loop refreshes tokens expiring within this window,
	// so an idle proxy never ends up holding an expired access token.
	backgroundRefreshWindow = 30 * time.Minute
	// maxBackoff caps the retry delay for accounts whose background refresh keeps failing.
	maxBackoff = 1 * time.Hour
)

type Refresher struct {
	client     *http.Client
	refreshURL string
	enc        *crypto.Encryptor
	refreshMu  sync.Map // map[uint]*sync.Mutex

	backoffMu   sync.Mutex
	failures    map[uint]int
	nextAttempt map[uint]time.Time
}

func New(refreshURL string, enc *crypto.Encryptor) *Refresher {
	return &Refresher{
		client:      &http.Client{Timeout: 30 * time.Second},
		refreshURL:  refreshURL,
		enc:         enc,
		failures:    make(map[uint]int),
		nextAttempt: make(map[uint]time.Time),
	}
}

type refreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
}

// RefreshToken exchanges the account's refresh token for a new access token.
// account.AccessToken and account.RefreshToken must hold DECRYPTED values.
// On success the DB row is updated (encrypted) and the in-memory account holds
// the new decrypted tokens.
func (r *Refresher) RefreshToken(db *gorm.DB, account *database.ClaudeAccount) error {
	if account.RefreshToken == "" {
		return fmt.Errorf("account has no refresh token")
	}

	body, _ := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": account.RefreshToken,
		"client_id":     claudeClientID,
	})

	req, err := http.NewRequest("POST", r.refreshURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("refresh failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var result refreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if result.AccessToken == "" {
		return fmt.Errorf("no access token in refresh response")
	}

	var expiresAt time.Time
	if result.ExpiresAt > 0 {
		// milliseconds timestamp
		expiresAt = time.UnixMilli(result.ExpiresAt)
	} else if result.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	} else {
		expiresAt = time.Now().Add(1 * time.Hour)
	}

	// Encrypt new tokens. Refresh tokens rotate, so the returned one (if any)
	// replaces the old one, which is no longer valid.
	newRefresh := account.RefreshToken
	if result.RefreshToken != "" {
		newRefresh = result.RefreshToken
	}
	encAccess, err := r.enc.Encrypt(result.AccessToken)
	if err != nil {
		return err
	}
	encRefresh, err := r.enc.Encrypt(newRefresh)
	if err != nil {
		return err
	}

	now := time.Now()
	updates := map[string]interface{}{
		"access_token":  encAccess,
		"refresh_token": encRefresh,
		"expires_at":    expiresAt,
		"last_error":    "",
		"last_used_at":  now,
	}
	// A successful refresh clears refresh-related errors, but must not
	// un-exhaust an account that hit its rate limit.
	if account.Status != "exhausted" {
		updates["status"] = "active"
	}
	if err := db.Model(&database.ClaudeAccount{}).Where("id = ?", account.ID).Updates(updates).Error; err != nil {
		return err
	}

	// Keep the dedup hash in step with the rotated refresh token. Done separately
	// so a hash conflict can never cause the rotated token itself to be lost.
	if result.RefreshToken != "" {
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(newRefresh)))
		if err := db.Model(&database.ClaudeAccount{}).Where("id = ?", account.ID).
			Update("refresh_token_hash", hash).Error; err != nil {
			log.Printf("oauth: account %d: could not update refresh token hash: %v", account.ID, err)
		}
	}

	// Update in-memory account for immediate use
	account.AccessToken = result.AccessToken
	account.RefreshToken = newRefresh
	account.ExpiresAt = expiresAt
	if account.Status != "exhausted" {
		account.Status = "active"
	}
	account.LastError = ""
	account.LastUsedAt = &now

	return nil
}

// EnsureValid refreshes the token if it expires within 5 minutes.
// account must hold DECRYPTED tokens; on return it holds a decrypted, valid access token.
func (r *Refresher) EnsureValid(db *gorm.DB, account *database.ClaudeAccount) error {
	if time.Until(account.ExpiresAt) > requestRefreshWindow {
		return nil
	}
	_, err := r.refreshIfExpiring(db, account, requestRefreshWindow)
	return err
}

// refreshIfExpiring takes the per-account lock, reloads the account from the DB
// (another goroutine may have refreshed it already), decrypts its tokens and
// refreshes them if they expire within `window`. On return `account` holds
// decrypted tokens. Reports whether a refresh was actually performed.
func (r *Refresher) refreshIfExpiring(db *gorm.DB, account *database.ClaudeAccount, window time.Duration) (bool, error) {
	val, _ := r.refreshMu.LoadOrStore(account.ID, &sync.Mutex{})
	mu := val.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	var fresh database.ClaudeAccount
	if err := db.First(&fresh, account.ID).Error; err != nil {
		return false, err
	}
	// Rows in the DB hold encrypted tokens; they must be decrypted before use.
	// (Previously the reloaded ciphertext was sent as the refresh token, which
	// Anthropic rejected with HTTP 400, so automatic refresh never worked.)
	access, err := r.enc.Decrypt(fresh.AccessToken)
	if err != nil {
		return false, fmt.Errorf("decrypt access token: %w", err)
	}
	refresh, err := r.enc.Decrypt(fresh.RefreshToken)
	if err != nil {
		return false, fmt.Errorf("decrypt refresh token: %w", err)
	}
	fresh.AccessToken = access
	fresh.RefreshToken = refresh
	*account = fresh

	if time.Until(account.ExpiresAt) > window {
		return false, nil
	}
	if err := r.RefreshToken(db, account); err != nil {
		return false, err
	}
	return true, nil
}

// StartAutoRefresh launches a background goroutine that proactively refreshes
// OAuth tokens before they expire, so accounts stay usable even when nobody
// sends requests for hours. Stops when ctx is cancelled.
func (r *Refresher) StartAutoRefresh(ctx context.Context, db *gorm.DB, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		log.Printf("oauth: background token refresh enabled (check every %s, refresh %s before expiry)", interval, backgroundRefreshWindow)
		r.refreshExpiring(db)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.refreshExpiring(db)
			}
		}
	}()
}

// refreshExpiring refreshes every OAuth account whose token expires within the
// background window. Accounts that keep failing are retried with exponential
// backoff (5m, 10m, 20m, ... capped at 1h) to avoid hammering the token endpoint.
func (r *Refresher) refreshExpiring(db *gorm.DB) {
	var accounts []database.ClaudeAccount
	if err := db.Find(&accounts).Error; err != nil {
		log.Printf("oauth: background refresh: failed to list accounts: %v", err)
		return
	}
	for i := range accounts {
		acc := &accounts[i]
		if acc.AccountType == "apikey" {
			continue
		}
		if time.Until(acc.ExpiresAt) > backgroundRefreshWindow {
			continue
		}
		if !r.dueForAttempt(acc.ID) {
			continue
		}
		refreshed, err := r.refreshIfExpiring(db, acc, backgroundRefreshWindow)
		if err != nil {
			delay := r.recordFailure(acc.ID)
			log.Printf("oauth: background refresh failed for account %d (%s): %v (retry in %s)", acc.ID, acc.Name, err, delay)
			continue
		}
		r.recordSuccess(acc.ID)
		if refreshed {
			log.Printf("oauth: refreshed token for account %d (%s), expires %s", acc.ID, acc.Name, acc.ExpiresAt.UTC().Format(time.RFC3339))
		}
	}
}

func (r *Refresher) dueForAttempt(id uint) bool {
	r.backoffMu.Lock()
	defer r.backoffMu.Unlock()
	next, ok := r.nextAttempt[id]
	return !ok || !time.Now().Before(next)
}

func (r *Refresher) recordFailure(id uint) time.Duration {
	r.backoffMu.Lock()
	defer r.backoffMu.Unlock()
	r.failures[id]++
	delay := 5 * time.Minute
	for i := 1; i < r.failures[id] && delay < maxBackoff; i++ {
		delay *= 2
	}
	if delay > maxBackoff {
		delay = maxBackoff
	}
	r.nextAttempt[id] = time.Now().Add(delay)
	return delay
}

func (r *Refresher) recordSuccess(id uint) {
	r.backoffMu.Lock()
	defer r.backoffMu.Unlock()
	delete(r.failures, id)
	delete(r.nextAttempt, id)
}
