package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"codex-proxy/internal/config"
	"codex-proxy/internal/crypto"
	"codex-proxy/internal/database"
	"codex-proxy/internal/oauth"
	"codex-proxy/internal/pool"

	"gorm.io/gorm"
)

var errUnknownPool = errors.New("unknown pool")

type AccountsHandler struct {
	db      *gorm.DB
	enc     *crypto.Encryptor
	oauth   *oauth.Refresher
	poolMgr *pool.Manager
	cfg     *config.Config
}

func NewAccountsHandler(db *gorm.DB, enc *crypto.Encryptor, oauthRefresher *oauth.Refresher, poolMgr *pool.Manager, cfg *config.Config) *AccountsHandler {
	return &AccountsHandler{db: db, enc: enc, oauth: oauthRefresher, poolMgr: poolMgr, cfg: cfg}
}

// upsertOAuthAccount creates or updates an account based on refresh token hash (dedup).
// Returns the account and true if it was updated (existing), false if created (new).
func (h *AccountsHandler) upsertOAuthAccount(name string, creds oauth.CredentialSet, ownerUserID *uint) (*database.CodexAccount, bool, error) {
	encAccess, err := h.enc.Encrypt(creds.AccessToken)
	if err != nil {
		return nil, false, fmt.Errorf("encrypt access: %w", err)
	}
	encRefresh, err := h.enc.Encrypt(creds.RefreshToken)
	if err != nil {
		return nil, false, fmt.Errorf("encrypt refresh: %w", err)
	}
	encID, err := h.enc.Encrypt(creds.IDToken)
	if err != nil {
		return nil, false, fmt.Errorf("encrypt ID token: %w", err)
	}
	hash := oauth.RefreshTokenHash(creds.RefreshToken)

	// The refresh token rotates. The ChatGPT account ID lets a re-import update
	// the same account even when the local Codex client refreshed first.
	var existing database.CodexAccount
	query := h.db.Where("refresh_token_hash = ?", hash)
	if creds.AccountID != "" {
		query = query.Or("chat_gpt_account_id = ?", creds.AccountID)
	}
	if err := query.First(&existing).Error; err == nil {
		// Update existing
		updates := map[string]interface{}{
			"access_token":          encAccess,
			"refresh_token":         encRefresh,
			"refresh_token_hash":    hash,
			"id_token":              encID,
			"chat_gpt_account_id":   creds.AccountID,
			"o_auth_issuer":         creds.Issuer,
			"o_auth_client_id":      creds.ClientID,
			"o_auth_login_owner_id": creds.LoginOwnerID,
			"o_auth_provider":       "codex",
			"o_auth_subject":        "",
			"o_auth_host_id":        "",
			"expires_at":            creds.ExpiresAt,
			"status":                "active",
			"last_error":            "",
		}
		if ownerUserID != nil {
			updates["owner_user_id"] = ownerUserID
		}
		if err := h.db.Model(&existing).Updates(updates).Error; err != nil {
			return nil, false, fmt.Errorf("update: %w", err)
		}
		return &existing, true, nil
	}

	// Create new
	account := database.CodexAccount{
		Name:              name,
		AccountType:       "oauth",
		AccessToken:       encAccess,
		RefreshToken:      encRefresh,
		RefreshTokenHash:  hash,
		IDToken:           encID,
		ChatGPTAccountID:  creds.AccountID,
		OAuthIssuer:       creds.Issuer,
		OAuthClientID:     creds.ClientID,
		OAuthLoginOwnerID: creds.LoginOwnerID,
		OAuthProvider:     "codex",
		ExpiresAt:         creds.ExpiresAt,
		Status:            "active",
		OwnerUserID:       ownerUserID,
	}
	if err := h.db.Create(&account).Error; err != nil {
		return nil, false, fmt.Errorf("create: %w", err)
	}
	return &account, false, nil
}

func (h *AccountsHandler) List(w http.ResponseWriter, r *http.Request) {
	var accounts []database.CodexAccount
	if err := h.db.Preload("Pools").Find(&accounts).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to fetch accounts"))
		return
	}
	writeJSON(w, http.StatusOK, accounts)
}

func (h *AccountsHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name            string  `json:"name"`
		PoolIDs         *[]uint `json:"pool_ids"`
		AccountType     string  `json:"account_type"`     // "oauth" (default) or "apikey"
		CredentialsJSON string  `json:"credentials_json"` // for oauth
		APIKey          string  `json:"api_key"`          // for apikey
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid request body"))
		return
	}

	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, errResp("name is required"))
		return
	}
	var poolIDs []uint
	if req.PoolIDs != nil {
		validated, err := validatePoolIDs(h.db, *req.PoolIDs)
		if err != nil {
			if errors.Is(err, errUnknownPool) {
				writeJSON(w, http.StatusBadRequest, errResp(err.Error()))
			} else {
				writeJSON(w, http.StatusInternalServerError, errResp("failed to validate pools"))
			}
			return
		}
		poolIDs = validated
	}

	var account database.CodexAccount
	updatedExisting := false

	if req.AccountType == "apikey" {
		// API key account
		if req.APIKey == "" {
			writeJSON(w, http.StatusBadRequest, errResp("api_key is required for API key accounts"))
			return
		}
		encKey, err := h.enc.Encrypt(req.APIKey)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errResp("failed to encrypt API key"))
			return
		}
		encEmpty, err := h.enc.Encrypt("")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errResp("failed to encrypt"))
			return
		}
		account = database.CodexAccount{
			Name:         req.Name,
			AccountType:  "apikey",
			AccessToken:  encKey,
			RefreshToken: encEmpty,
			IDToken:      encEmpty,
			ExpiresAt:    time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
			Status:       "active",
		}
	} else {
		// OAuth account (default)
		if req.CredentialsJSON == "" {
			writeJSON(w, http.StatusBadRequest, errResp("credentials_json is required for OAuth accounts"))
			return
		}
		creds, err := oauth.ParseAuthJSON([]byte(req.CredentialsJSON))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errResp(err.Error()))
			return
		}
		acc, updated, err := h.upsertOAuthAccount(req.Name, creds, nil)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errResp("failed to create account: "+err.Error()))
			return
		}
		account = *acc
		updatedExisting = updated
	}

	if account.ID == 0 {
		if err := h.db.Create(&account).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, errResp("failed to create account"))
			return
		}
	}

	// A missing pool_ids field on a deduplicated import preserves the existing
	// assignments; an explicit empty list intentionally unassigns all pools.
	if !updatedExisting || req.PoolIDs != nil {
		if err := syncAccountPools(h.db, account.ID, poolIDs); err != nil {
			writeJSON(w, http.StatusInternalServerError, errResp("failed to assign account pools"))
			return
		}
	}

	h.db.Preload("Pools").First(&account, account.ID)
	if updatedExisting {
		details := "deduplicated — updated existing"
		if req.PoolIDs != nil {
			details += " and synchronized pools"
		}
		logAudit(h.db, r, "create_account", "account:"+req.Name, details)
		writeJSON(w, http.StatusOK, account)
		return
	}
	logAudit(h.db, r, "create_account", "account:"+req.Name, "")
	writeJSON(w, http.StatusCreated, account)
}

func (h *AccountsHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid id"))
		return
	}

	var account database.CodexAccount
	if err := h.db.Preload("Pools").First(&account, id).Error; err != nil {
		writeJSON(w, http.StatusNotFound, errResp("account not found"))
		return
	}
	writeJSON(w, http.StatusOK, account)
}

func (h *AccountsHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid id"))
		return
	}

	var req struct {
		Name        string  `json:"name"`
		PoolIDs     *[]uint `json:"pool_ids"`
		OwnerUserID *uint   `json:"owner_user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid request body"))
		return
	}
	var validatedPoolIDs []uint
	if req.PoolIDs != nil {
		validatedPoolIDs, err = validatePoolIDs(h.db, *req.PoolIDs)
		if err != nil {
			if errors.Is(err, errUnknownPool) {
				writeJSON(w, http.StatusBadRequest, errResp(err.Error()))
			} else {
				writeJSON(w, http.StatusInternalServerError, errResp("failed to validate pools"))
			}
			return
		}
	}

	updates := map[string]interface{}{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.OwnerUserID != nil {
		if *req.OwnerUserID == 0 {
			updates["owner_user_id"] = nil // unassign
		} else {
			updates["owner_user_id"] = *req.OwnerUserID
		}
	}

	if len(updates) > 0 {
		if err := h.db.Model(&database.CodexAccount{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			writeJSON(w, http.StatusInternalServerError, errResp("failed to update account"))
			return
		}
	}

	// Sync pool assignments if provided
	if req.PoolIDs != nil {
		if err := syncAccountPools(h.db, id, validatedPoolIDs); err != nil {
			writeJSON(w, http.StatusInternalServerError, errResp("failed to assign account pools"))
			return
		}
	}

	var account database.CodexAccount
	h.db.Preload("Pools").First(&account, id)
	logAudit(h.db, r, "update_account", fmt.Sprintf("account:%s", account.Name), "")
	writeJSON(w, http.StatusOK, account)
}

// validatePoolIDs removes zero and duplicate values and rejects references to
// pools that do not exist. This prevents silently creating an unassigned
// account when the dashboard sends a stale pool selection.
func validatePoolIDs(db *gorm.DB, poolIDs []uint) ([]uint, error) {
	seen := make(map[uint]struct{}, len(poolIDs))
	normalized := make([]uint, 0, len(poolIDs))
	for _, poolID := range poolIDs {
		if poolID == 0 {
			continue
		}
		if _, exists := seen[poolID]; exists {
			continue
		}
		seen[poolID] = struct{}{}
		normalized = append(normalized, poolID)
	}
	if len(normalized) == 0 {
		return normalized, nil
	}

	var count int64
	if err := db.Model(&database.Pool{}).Where("id IN ?", normalized).Count(&count).Error; err != nil {
		return nil, err
	}
	if count != int64(len(normalized)) {
		return nil, fmt.Errorf("%w: one or more selected pools no longer exist", errUnknownPool)
	}
	return normalized, nil
}

func syncAccountPools(db *gorm.DB, accountID uint, poolIDs []uint) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("account_id = ?", accountID).Delete(&database.AccountPool{}).Error; err != nil {
			return err
		}
		for _, poolID := range poolIDs {
			if err := tx.Create(&database.AccountPool{AccountID: accountID, PoolID: poolID}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (h *AccountsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid id"))
		return
	}

	var account database.CodexAccount
	if err := h.db.First(&account, id).Error; err != nil {
		writeJSON(w, http.StatusNotFound, errResp("account not found"))
		return
	}
	h.db.Where("account_id = ?", id).Delete(&database.AccountPool{})
	h.db.Where("account_id = ?", id).Delete(&database.AccountQuota{})
	if err := h.db.Delete(&database.CodexAccount{}, id).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to delete account"))
		return
	}
	logAudit(h.db, r, "delete_account", "account:"+account.Name, "")
	writeJSON(w, http.StatusOK, map[string]string{"message": "account deleted"})
}

func (h *AccountsHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid id"))
		return
	}

	var account database.CodexAccount
	if err := h.db.First(&account, id).Error; err != nil {
		writeJSON(w, http.StatusNotFound, errResp("account not found"))
		return
	}

	if account.AccountType == "apikey" {
		writeJSON(w, http.StatusBadRequest, errResp("API key accounts don't need token refresh"))
		return
	}

	// Decrypt before passing to oauth refresher
	access, err := h.enc.Decrypt(account.AccessToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to decrypt token"))
		return
	}
	refresh, err := h.enc.Decrypt(account.RefreshToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to decrypt token"))
		return
	}
	account.AccessToken = access
	account.RefreshToken = refresh
	idToken := ""
	if account.IDToken != "" {
		idToken, err = h.enc.Decrypt(account.IDToken)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errResp("failed to decrypt ID token"))
			return
		}
	}
	account.IDToken = idToken

	if err := h.oauth.RefreshToken(h.db, &account); err != nil {
		writeJSON(w, http.StatusBadGateway, errResp("token refresh failed: "+err.Error()))
		return
	}

	logAudit(h.db, r, "refresh_account", "account:"+account.Name, "")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "token refreshed",
		"expires_at": account.ExpiresAt,
	})
}

func (h *AccountsHandler) Reset(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid id"))
		return
	}

	if err := h.poolMgr.ResetAccount(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to reset account"))
		return
	}

	logAudit(h.db, r, "reset_account", fmt.Sprintf("account:%d", id), "")
	writeJSON(w, http.StatusOK, map[string]string{"message": "account reset to active"})
}

// GET /api/admin/accounts/{id}/stats — usage stats for a specific account
func (h *AccountsHandler) Stats(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid id"))
		return
	}

	type periodStats struct {
		Requests     int64   `json:"requests"`
		InputTokens  int64   `json:"input_tokens"`
		OutputTokens int64   `json:"output_tokens"`
		EstCostUSD   float64 `json:"est_cost_usd"`
	}

	queryStats := func(since time.Time) periodStats {
		var reqs, inp, out int64
		h.db.Model(&database.UsageLog{}).
			Where("account_id = ? AND created_at >= ?", id, since).
			Select("COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0)").
			Row().Scan(&reqs, &inp, &out)

		// Compute cost by model breakdown
		type modelRow struct {
			Model        string
			InputTokens  int64
			OutputTokens int64
		}
		var models []modelRow
		h.db.Model(&database.UsageLog{}).
			Where("account_id = ? AND created_at >= ?", id, since).
			Select("model, SUM(input_tokens) as input_tokens, SUM(output_tokens) as output_tokens").
			Group("model").Scan(&models)
		var cost float64
		for _, m := range models {
			cost += EstimateCost(m.Model, m.InputTokens, m.OutputTokens)
		}

		return periodStats{Requests: reqs, InputTokens: inp, OutputTokens: out, EstCostUSD: cost}
	}

	now := time.Now().UTC()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"today": queryStats(now.Truncate(24 * time.Hour)),
		"week":  queryStats(now.AddDate(0, 0, -7)),
		"total": queryStats(time.Time{}),
	})
}

func (h *AccountsHandler) Test(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid id"))
		return
	}

	var account database.CodexAccount
	if err := h.db.First(&account, id).Error; err != nil {
		writeJSON(w, http.StatusNotFound, errResp("account not found"))
		return
	}
	access, err := h.enc.Decrypt(account.AccessToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to decrypt token"))
		return
	}

	upstream := h.cfg.OpenAIAPIURL
	testURL := strings.TrimRight(upstream, "/") + "/models"
	if account.AccountType == "oauth" && account.OAuthProvider != "siwc" {
		upstream = h.cfg.ChatGPTURL
		testURL = strings.TrimRight(upstream, "/") + "/models?client_version=0.0.0"
	}
	req, _ := http.NewRequest(http.MethodGet, testURL, nil)
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Accept", "application/json")
	if account.AccountType == "oauth" && account.OAuthProvider != "siwc" && account.ChatGPTAccountID != "" {
		req.Header.Set("ChatGPT-Account-ID", account.ChatGPTAccountID)
		req.Header.Set("Originator", "codex_cli_rs")
		req.Header.Set("User-Agent", "ourcodex-account-test")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errResp("connection failed: "+err.Error()))
		return
	}
	defer resp.Body.Close()

	result := map[string]interface{}{
		"status_code": resp.StatusCode,
		"ok":          resp.StatusCode == http.StatusOK,
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		var upstreamError struct {
			Error struct {
				Message string `json:"message"`
				Code    string `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &upstreamError) == nil {
			if upstreamError.Error.Message != "" {
				result["upstream_error"] = upstreamError.Error.Message
			}
			if upstreamError.Error.Code != "" {
				result["upstream_code"] = upstreamError.Error.Code
			}
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// GET /api/admin/accounts/{id}/credentials — returns decrypted tokens in credentials.json format
func (h *AccountsHandler) Credentials(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid id"))
		return
	}

	var account database.CodexAccount
	if err := h.db.First(&account, id).Error; err != nil {
		writeJSON(w, http.StatusNotFound, errResp("account not found"))
		return
	}
	if account.OAuthProvider == "siwc" {
		writeJSON(w, http.StatusBadRequest, errResp("Sign in with ChatGPT credentials are managed by OurCodex and cannot be exported as Codex auth.json"))
		return
	}

	access, err := h.enc.Decrypt(account.AccessToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to decrypt access token"))
		return
	}
	refresh, err := h.enc.Decrypt(account.RefreshToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to decrypt refresh token"))
		return
	}

	idToken := ""
	if account.IDToken != "" {
		idToken, err = h.enc.Decrypt(account.IDToken)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errResp("failed to decrypt ID token"))
			return
		}
	}
	writeJSON(w, http.StatusOK, oauth.BuildAuthFile(oauth.CredentialSet{
		IDToken:      idToken,
		AccessToken:  access,
		RefreshToken: refresh,
		AccountID:    account.ChatGPTAccountID,
		Issuer:       account.OAuthIssuer,
		ClientID:     account.OAuthClientID,
		LoginOwnerID: account.OAuthLoginOwnerID,
		ExpiresAt:    account.ExpiresAt,
	}))
}

// DELETE /api/admin/accounts/{id}/pool?pool_id=N — unlinks the account from a pool (or all pools if no pool_id)
func (h *AccountsHandler) Unlink(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid id"))
		return
	}

	poolIDStr := r.URL.Query().Get("pool_id")
	var result *gorm.DB
	if poolIDStr != "" {
		result = h.db.Where("account_id = ? AND pool_id = ?", id, poolIDStr).Delete(&database.AccountPool{})
	} else {
		result = h.db.Where("account_id = ?", id).Delete(&database.AccountPool{})
	}
	if result.Error != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to unlink account"))
		return
	}
	logAudit(h.db, r, "unlink_account", fmt.Sprintf("account:%d", id), "pool_id="+poolIDStr)
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/admin/accounts/{id}/quota — returns cached OpenAI usage quota for this account
func (h *AccountsHandler) Quota(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid id"))
		return
	}

	var account database.CodexAccount
	if err := h.db.First(&account, id).Error; err != nil {
		writeJSON(w, http.StatusNotFound, errResp("account not found"))
		return
	}

	if account.AccountType == "apikey" {
		writeJSON(w, http.StatusBadRequest, errResp("quota check only available for OAuth accounts"))
		return
	}

	var quota database.AccountQuota
	if err := h.db.Where("account_id = ?", id).First(&quota).Error; err != nil {
		writeJSON(w, http.StatusNotFound, errResp("no rate-limit data yet — use this account for a Codex request first"))
		return
	}

	writeJSON(w, http.StatusOK, quota)
}

// GET /api/admin/quotas — returns all account quotas (for Quotas page)
func (h *AccountsHandler) AllQuotas(w http.ResponseWriter, r *http.Request) {
	// Return ALL OAuth accounts, with quota data if available
	var accounts []database.CodexAccount
	h.db.Preload("Pools").Where("account_type = ?", "oauth").Find(&accounts)

	// Sign in with ChatGPT accounts never send x-codex rate-limit headers, and
	// OpenAI exposes no plan-usage percentage for them, so report the traffic
	// OurCodex observed over the five-hour and weekly windows OpenAI uses.
	now := time.Now()
	usage5h := accountUsageSince(h.db, now.Add(-5*time.Hour))
	usage7d := accountUsageSince(h.db, now.Add(-7*24*time.Hour))

	type quotaWithAccount struct {
		database.AccountQuota
		AccountName   string           `json:"account_name"`
		AccountType   string           `json:"account_type"`
		OAuthProvider string           `json:"oauth_provider"`
		Status        string           `json:"status"`
		ExhaustedAt   *time.Time       `json:"exhausted_at,omitempty"`
		LastUsedAt    *time.Time       `json:"last_used_at,omitempty"`
		LastError     string           `json:"last_error,omitempty"`
		Pools         []*database.Pool `json:"pools,omitempty"`
		Usage5h       windowUsage      `json:"usage_5h"`
		Usage7d       windowUsage      `json:"usage_7d"`
	}

	result := make([]quotaWithAccount, 0, len(accounts))
	for _, acc := range accounts {
		entry := quotaWithAccount{
			AccountName:   acc.Name,
			AccountType:   acc.AccountType,
			OAuthProvider: acc.OAuthProvider,
			Status:        acc.Status,
			LastUsedAt:    acc.LastUsedAt,
			LastError:     acc.LastError,
			Pools:         acc.Pools,
			Usage5h:       usage5h[acc.ID],
			Usage7d:       usage7d[acc.ID],
		}
		if acc.Status == "exhausted" {
			entry.ExhaustedAt = acc.ExhaustedAt
		}
		// Try to find quota data for this account
		var q database.AccountQuota
		if err := h.db.Where("account_id = ?", acc.ID).First(&q).Error; err == nil {
			entry.AccountQuota = q
		} else {
			// No quota data yet — set account_id so frontend can identify it
			entry.AccountQuota.AccountID = acc.ID
		}
		result = append(result, entry)
	}

	writeJSON(w, http.StatusOK, result)
}

// windowUsage is the traffic an account served through OurCodex in a window.
type windowUsage struct {
	Requests int64 `json:"requests"`
	Tokens   int64 `json:"tokens"`
}

// accountUsageSince sums token-bearing responses per account since a time.
// Responses without tokens (errors, model listings) are not counted.
func accountUsageSince(db *gorm.DB, since time.Time) map[uint]windowUsage {
	var rows []struct {
		AccountID uint
		Requests  int64
		Tokens    int64
	}
	db.Model(&database.UsageLog{}).
		Select("account_id, COUNT(*) AS requests, COALESCE(SUM(input_tokens + output_tokens), 0) AS tokens").
		Where("created_at >= ? AND input_tokens + output_tokens > 0", since).
		Group("account_id").
		Scan(&rows)
	usage := make(map[uint]windowUsage, len(rows))
	for _, row := range rows {
		usage[row.AccountID] = windowUsage{Requests: row.Requests, Tokens: row.Tokens}
	}
	return usage
}

// POST /api/admin/accounts/{id}/toggle — toggle active/disabled status
func (h *AccountsHandler) ToggleStatus(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid id"))
		return
	}

	var account database.CodexAccount
	if err := h.db.First(&account, id).Error; err != nil {
		writeJSON(w, http.StatusNotFound, errResp("account not found"))
		return
	}

	newStatus := "active"
	if account.Status != "disabled" {
		newStatus = "disabled"
	}

	h.db.Model(&account).Update("status", newStatus)
	logAudit(h.db, r, "toggle_account", fmt.Sprintf("account:%s", account.Name), fmt.Sprintf("status=%s", newStatus))
	writeJSON(w, http.StatusOK, map[string]string{"status": newStatus})
}

// POST /api/admin/accounts/import-credentials — import account from raw credentials.json
func (h *AccountsHandler) ImportCredentials(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid Codex auth.json"))
		return
	}
	creds, err := oauth.ParseAuthJSON(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp(err.Error()))
		return
	}
	account, updated, err := h.upsertOAuthAccount("Imported "+time.Now().Format("2006-01-02 15:04"), creds, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed: "+err.Error()))
		return
	}

	action := "import_credentials"
	if updated {
		action = "import_credentials_updated"
	}
	logAudit(h.db, r, action, fmt.Sprintf("account:%d", account.ID), "")
	writeJSON(w, http.StatusCreated, account)
}

// POST /api/import/{token} — public pre-auth import using setup token
func (h *AccountsHandler) PublicImport(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")

	var setup database.SetupToken
	if err := h.db.Where("token = ? AND expires_at > ?", token, time.Now()).First(&setup).Error; err != nil {
		writeJSON(w, http.StatusNotFound, errResp("invalid or expired setup token"))
		return
	}

	var user database.User
	if err := h.db.First(&user, setup.UserID).Error; err != nil {
		writeJSON(w, http.StatusNotFound, errResp("user not found"))
		return
	}

	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid Codex auth.json"))
		return
	}
	creds, err := oauth.ParseAuthJSON(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp(err.Error()))
		return
	}
	account, updated, err := h.upsertOAuthAccount(user.Name+" (imported)", creds, &user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed: "+err.Error()))
		return
	}

	// Link to user's pools if new account
	if !updated {
		var poolIDs []uint
		h.db.Table("user_pools").Where("user_id = ?", user.ID).Pluck("pool_id", &poolIDs)
		for _, pid := range poolIDs {
			h.db.Create(&database.AccountPool{AccountID: account.ID, PoolID: pid})
		}
	}

	status := "created"
	if updated {
		status = "updated (duplicate detected)"
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message":    "account " + status,
		"account_id": account.ID,
	})
}
