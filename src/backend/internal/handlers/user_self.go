package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"codex-proxy/internal/crypto"
	"codex-proxy/internal/database"
	"codex-proxy/internal/oauth"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var errInvalidToken = errors.New("invalid token")

// UserSelfHandler serves /api/user/* — authenticated with the sk-proxy-* token,
// not the admin JWT. Allows users to check their own info and usage.
type UserSelfHandler struct {
	db      *gorm.DB
	distDir string
	enc     *crypto.Encryptor
}

func NewUserSelfHandler(db *gorm.DB, distDir string, enc *crypto.Encryptor) *UserSelfHandler {
	return &UserSelfHandler{db: db, distDir: distDir, enc: enc}
}

func (h *UserSelfHandler) extractUser(r *http.Request) (*database.User, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, errInvalidToken
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == auth {
		return nil, errInvalidToken
	}

	var user database.User
	if err := h.db.Preload("Pools").Where("api_token = ? AND active = ?", token, true).First(&user).Error; err != nil {
		return nil, errInvalidToken
	}
	return &user, nil
}

// GET /api/user/me — returns user info with quota usage (no token exposed)
func (h *UserSelfHandler) Me(w http.ResponseWriter, r *http.Request) {
	user, err := h.extractUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errResp("invalid token"))
		return
	}

	now := time.Now().UTC()
	today := now.Truncate(24 * time.Hour)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	var dailyUsed, monthlyUsed int64
	h.db.Model(&database.UsageLog{}).
		Where("user_id = ? AND created_at >= ?", user.ID, today).
		Select("COALESCE(SUM(input_tokens + output_tokens), 0)").
		Row().Scan(&dailyUsed)
	h.db.Model(&database.UsageLog{}).
		Where("user_id = ? AND created_at >= ?", user.ID, monthStart).
		Select("COALESCE(SUM(input_tokens + output_tokens), 0)").
		Row().Scan(&monthlyUsed)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":         user.ID,
		"name":       user.Name,
		"pools":      user.Pools,
		"active":     user.Active,
		"created_at": user.CreatedAt,
		"quota": map[string]interface{}{
			"daily_used":     dailyUsed,
			"daily_limit":    user.DailyTokenQuota,
			"monthly_used":   monthlyUsed,
			"monthly_limit":  user.MonthlyTokenQuota,
			"monthly_budget": user.MonthlyBudgetUSD,
		},
	})
}

// GET /api/user/usage — returns this user's usage stats
func (h *UserSelfHandler) Usage(w http.ResponseWriter, r *http.Request) {
	user, err := h.extractUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errResp("invalid token"))
		return
	}

	var totalReqs int64
	var totalIn, totalOut int64
	h.db.Model(&database.UsageLog{}).Where("user_id = ?", user.ID).Count(&totalReqs)
	h.db.Model(&database.UsageLog{}).
		Where("user_id = ?", user.ID).
		Select("COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0)").
		Row().Scan(&totalIn, &totalOut)

	type dayStat struct {
		Day          string `json:"day"`
		TotalReqs    int64  `json:"total_requests"`
		InputTokens  int64  `json:"input_tokens"`
		OutputTokens int64  `json:"output_tokens"`
	}
	var byDay []dayStat
	h.db.Model(&database.UsageLog{}).
		Where("user_id = ? AND created_at >= ?", user.ID, time.Now().AddDate(0, 0, -7)).
		Select("DATE(created_at) as day, count(*) as total_reqs, COALESCE(SUM(input_tokens),0) as input_tokens, COALESCE(SUM(output_tokens),0) as output_tokens").
		Group("DATE(created_at)").
		Order("day ASC").
		Scan(&byDay)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_requests": totalReqs,
		"total_input":    totalIn,
		"total_output":   totalOut,
		"last_7_days":    byDay,
	})
}

// GET /api/user/update?platform=linux-amd64 — download latest cl binary with embedded key
func (h *UserSelfHandler) Update(w http.ResponseWriter, r *http.Request) {
	user, err := h.extractUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errResp("invalid token"))
		return
	}

	platform := r.URL.Query().Get("platform")
	if platform == "" {
		writeJSON(w, http.StatusBadRequest, errResp("platform query parameter required (e.g. linux-amd64)"))
		return
	}

	platformFiles := map[string]string{
		"linux-amd64":   "ourcodex-linux-amd64",
		"linux-arm64":   "ourcodex-linux-arm64",
		"darwin-amd64":  "ourcodex-darwin-amd64",
		"darwin-arm64":  "ourcodex-darwin-arm64",
		"windows-amd64": "ourcodex-windows-amd64.exe",
	}
	filename, ok := platformFiles[platform]
	if !ok {
		writeJSON(w, http.StatusBadRequest, errResp("unknown platform"))
		return
	}

	path := filepath.Join(h.distDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errResp("binary not available for this platform"))
		return
	}

	key := strings.ReplaceAll(uuid.New().String(), "-", "")
	patched := patchBinaryToken(data, key)

	// Record the download.
	h.db.Create(&database.UserBinaryDownload{
		UserID:       user.ID,
		Platform:     platform,
		BinaryKey:    key,
		DownloadedAt: time.Now(),
	})

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(patched)))
	w.Write(patched)
}

// POST /api/user/rotate-token — rotate own API token
func (h *UserSelfHandler) RotateToken(w http.ResponseWriter, r *http.Request) {
	user, err := h.extractUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errResp("invalid token"))
		return
	}

	newToken := "sk-proxy-" + strings.ReplaceAll(uuid.New().String(), "-", "")
	if err := h.db.Model(&database.User{}).Where("id = ?", user.ID).
		Update("api_token", newToken).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to rotate token"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"api_token": newToken})
}

// POST /api/user/import-account
// Imports ~/.codex/auth.json content into the proxy as a CodexAccount
// owned by this user. If an owned account already exists, it is updated.
func (h *UserSelfHandler) ImportAccount(w http.ResponseWriter, r *http.Request) {
	if h.enc == nil {
		writeJSON(w, http.StatusInternalServerError, errResp("encryption not configured"))
		return
	}

	user, err := h.extractUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errResp("invalid token"))
		return
	}

	var req struct {
		CredentialsJSON string `json:"credentials_json"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CredentialsJSON == "" {
		writeJSON(w, http.StatusBadRequest, errResp("credentials_json is required"))
		return
	}

	creds, err := oauth.ParseAuthJSON([]byte(req.CredentialsJSON))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp(err.Error()))
		return
	}

	// Resolve pool: prefer user's assigned pool, fall back to any available pool
	var poolID uint
	var poolEntry database.UserPool
	if err := h.db.Where("user_id = ?", user.ID).First(&poolEntry).Error; err == nil {
		poolID = poolEntry.PoolID
	} else {
		// No pool assigned to this user — use the first available pool
		var anyPool database.Pool
		if err := h.db.First(&anyPool).Error; err != nil {
			writeJSON(w, http.StatusBadRequest, errResp("no pools exist in the proxy yet — ask an administrator to create one"))
			return
		}
		poolID = anyPool.ID
	}

	encAccess, err := h.enc.Encrypt(creds.AccessToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to encrypt access token"))
		return
	}
	encRefresh, err := h.enc.Encrypt(creds.RefreshToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to encrypt refresh token"))
		return
	}

	encID, err := h.enc.Encrypt(creds.IDToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to encrypt ID token"))
		return
	}

	// Dedup by rotating refresh token, stable ChatGPT account, then owner.
	rtHash := oauth.RefreshTokenHash(creds.RefreshToken)

	var existing database.CodexAccount
	found := false
	if err := h.db.Where("refresh_token_hash = ? OR chat_gpt_account_id = ?", rtHash, creds.AccountID).First(&existing).Error; err == nil {
		found = true
	} else if err := h.db.Where("owner_user_id = ?", user.ID).First(&existing).Error; err == nil {
		found = true
	}

	if found {
		h.db.Model(&existing).Updates(map[string]interface{}{
			"access_token":          encAccess,
			"refresh_token":         encRefresh,
			"refresh_token_hash":    rtHash,
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
			"owner_user_id":         user.ID,
		})
		h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&database.AccountPool{AccountID: existing.ID, PoolID: poolID})
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message":    "account updated",
			"account_id": existing.ID,
		})
		return
	}

	account := database.CodexAccount{
		Name:              user.Name + " (personal)",
		AccessToken:       encAccess,
		RefreshToken:      encRefresh,
		RefreshTokenHash:  rtHash,
		IDToken:           encID,
		ChatGPTAccountID:  creds.AccountID,
		OAuthIssuer:       creds.Issuer,
		OAuthClientID:     creds.ClientID,
		OAuthLoginOwnerID: creds.LoginOwnerID,
		OAuthProvider:     "codex",
		ExpiresAt:         creds.ExpiresAt,
		AccountType:       "oauth",
		Status:            "active",
		OwnerUserID:       &user.ID,
	}
	if err := h.db.Create(&account).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to create account"))
		return
	}
	// Link account to pool via join table
	h.db.Create(&database.AccountPool{AccountID: account.ID, PoolID: poolID})

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message":    "account imported",
		"account_id": account.ID,
	})
}

// GET /api/user/pool-status — returns pools account summary + today/week usage for the CLI dashboard
// DELETE /api/user/owned-account — user deletes their own account from the proxy
func (h *UserSelfHandler) DeleteOwnedAccount(w http.ResponseWriter, r *http.Request) {
	user, err := h.extractUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errResp("invalid token"))
		return
	}

	var account database.CodexAccount
	if err := h.db.Where("owner_user_id = ?", user.ID).First(&account).Error; err != nil {
		writeJSON(w, http.StatusNotFound, errResp("no owned account"))
		return
	}

	// Clean up pool links
	h.db.Where("account_id = ?", account.ID).Delete(&database.AccountPool{})
	h.db.Delete(&account)

	writeJSON(w, http.StatusOK, map[string]string{"message": "account deleted"})
}

func (h *UserSelfHandler) PoolStatus(w http.ResponseWriter, r *http.Request) {
	user, err := h.extractUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errResp("invalid token"))
		return
	}

	var poolIDs []uint
	h.db.Table("user_pools").Where("user_id = ?", user.ID).Pluck("pool_id", &poolIDs)

	type accountCounts struct {
		Active    int64 `json:"active"`
		Exhausted int64 `json:"exhausted"`
		Error     int64 `json:"error"`
	}
	type poolEntry struct {
		ID       uint          `json:"id"`
		Name     string        `json:"name"`
		Accounts accountCounts `json:"accounts"`
	}

	poolEntries := make([]poolEntry, 0)
	for _, pid := range poolIDs {
		var p database.Pool
		if err := h.db.First(&p, pid).Error; err != nil {
			continue
		}
		var active, exhausted, errCount int64
		h.db.Model(&database.CodexAccount{}).Joins("JOIN account_pools ON account_pools.account_id = codex_accounts.id").Where("account_pools.pool_id = ? AND codex_accounts.status = ?", pid, "active").Count(&active)
		h.db.Model(&database.CodexAccount{}).Joins("JOIN account_pools ON account_pools.account_id = codex_accounts.id").Where("account_pools.pool_id = ? AND codex_accounts.status = ?", pid, "exhausted").Count(&exhausted)
		h.db.Model(&database.CodexAccount{}).Joins("JOIN account_pools ON account_pools.account_id = codex_accounts.id").Where("account_pools.pool_id = ? AND codex_accounts.status = ?", pid, "error").Count(&errCount)
		poolEntries = append(poolEntries, poolEntry{
			ID:   p.ID,
			Name: p.Name,
			Accounts: accountCounts{
				Active:    active,
				Exhausted: exhausted,
				Error:     errCount,
			},
		})
	}

	now := time.Now().UTC()
	today := now.Truncate(24 * time.Hour)
	weekStart := today.AddDate(0, 0, -7)

	type periodStats struct {
		Requests     int64 `json:"requests"`
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
	}

	var todayStats, weekStats periodStats
	h.db.Model(&database.UsageLog{}).
		Where("user_id = ? AND created_at >= ?", user.ID, today).
		Count(&todayStats.Requests)
	h.db.Model(&database.UsageLog{}).
		Where("user_id = ? AND created_at >= ?", user.ID, today).
		Select("COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0)").
		Row().Scan(&todayStats.InputTokens, &todayStats.OutputTokens)

	h.db.Model(&database.UsageLog{}).
		Where("user_id = ? AND created_at >= ?", user.ID, weekStart).
		Count(&weekStats.Requests)
	h.db.Model(&database.UsageLog{}).
		Where("user_id = ? AND created_at >= ?", user.ID, weekStart).
		Select("COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0)").
		Row().Scan(&weekStats.InputTokens, &weekStats.OutputTokens)

	// Owned account metadata + its own today/week usage stats
	type ownedAccountInfo struct {
		ID        uint        `json:"id"`
		Status    string      `json:"status"`
		ExpiresAt time.Time   `json:"expires_at"`
		LastError string      `json:"last_error,omitempty"`
		Today     periodStats `json:"today"`
		Week      periodStats `json:"week"`
	}
	var owned *ownedAccountInfo
	var account database.CodexAccount
	if h.db.Where("owner_user_id = ?", user.ID).First(&account).Error == nil {
		var accToday, accWeek periodStats
		h.db.Model(&database.UsageLog{}).
			Where("account_id = ? AND created_at >= ?", account.ID, today).
			Count(&accToday.Requests)
		h.db.Model(&database.UsageLog{}).
			Where("account_id = ? AND created_at >= ?", account.ID, today).
			Select("COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0)").
			Row().Scan(&accToday.InputTokens, &accToday.OutputTokens)

		h.db.Model(&database.UsageLog{}).
			Where("account_id = ? AND created_at >= ?", account.ID, weekStart).
			Count(&accWeek.Requests)
		h.db.Model(&database.UsageLog{}).
			Where("account_id = ? AND created_at >= ?", account.ID, weekStart).
			Select("COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0)").
			Row().Scan(&accWeek.InputTokens, &accWeek.OutputTokens)

		owned = &ownedAccountInfo{
			ID:        account.ID,
			Status:    account.Status,
			ExpiresAt: account.ExpiresAt,
			LastError: account.LastError,
			Today:     accToday,
			Week:      accWeek,
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pools":         poolEntries,
		"today":         todayStats,
		"week":          weekStats,
		"owned_account": owned,
	})
}

// GET /api/user/mcp-servers — returns MCP servers for client configuration
func (h *UserSelfHandler) MCPServers(w http.ResponseWriter, r *http.Request) {
	var servers []database.MCPServer
	h.db.Order("name").Find(&servers)
	writeJSON(w, http.StatusOK, servers)
}

// GET /api/user/owned-account
// Returns the current decrypted credentials for the account this user owns,
// in the ~/.codex/auth.json format. Used by ourcodex to keep local credentials in sync.
func (h *UserSelfHandler) OwnedAccount(w http.ResponseWriter, r *http.Request) {
	if h.enc == nil {
		writeJSON(w, http.StatusInternalServerError, errResp("encryption not configured"))
		return
	}

	user, err := h.extractUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errResp("invalid token"))
		return
	}

	var account database.CodexAccount
	if err := h.db.Where("owner_user_id = ?", user.ID).First(&account).Error; err != nil {
		writeJSON(w, http.StatusNotFound, errResp("no owned account"))
		return
	}
	if account.OAuthProvider == "siwc" {
		writeJSON(w, http.StatusNotFound, errResp("owned account is managed by Sign in with ChatGPT"))
		return
	}

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
