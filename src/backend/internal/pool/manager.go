package pool

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"codex-proxy/internal/crypto"
	"codex-proxy/internal/database"
	"codex-proxy/internal/oauth"
	"codex-proxy/internal/webhook"

	"gorm.io/gorm"
)

var ErrNoActiveAccounts = errors.New("no active accounts available in pool")

// WebhookDispatcher is a subset of webhook.Dispatcher to avoid tight coupling.
type WebhookDispatcher interface {
	Dispatch(event string, payload interface{})
}

type Manager struct {
	db         *gorm.DB
	oauth      *oauth.Refresher
	enc        *crypto.Encryptor
	webhooks   WebhookDispatcher // may be nil
	mu         sync.Mutex
	roundRobin map[uint]int
}

func New(db *gorm.DB, oauthRefresher *oauth.Refresher, enc *crypto.Encryptor, webhooks *webhook.Dispatcher) *Manager {
	return &Manager{
		db:         db,
		oauth:      oauthRefresher,
		enc:        enc,
		webhooks:   webhooks,
		roundRobin: make(map[uint]int),
	}
}

// StartHealthCheck periodically tests every account and marks unhealthy ones.
// It performs a lightweight HEAD/GET to the upstream to verify token validity.
func (m *Manager) StartHealthCheck(ctx context.Context, interval time.Duration, apiURL, chatGPTURL string) {
	if interval <= 0 {
		return
	}
	go func() {
		log.Printf("pool: health-check enabled (interval: %s)", interval)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var accounts []database.CodexAccount
				if err := m.db.Where("status = ?", "active").Find(&accounts).Error; err != nil {
					log.Printf("pool health-check: failed to list accounts: %v", err)
					continue
				}
				for _, acc := range accounts {
					if err := m.decryptAccount(&acc); err != nil {
						continue
					}
					if acc.AccountType != "apikey" {
						if err := m.oauth.EnsureValid(m.db, &acc); err != nil {
							m.MarkError(acc.ID, "health-check refresh: "+err.Error())
							continue
						}
					}
					upstreamURL := apiURL
					if acc.AccountType != "apikey" && acc.OAuthProvider != "siwc" {
						upstreamURL = chatGPTURL
					}
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(upstreamURL, "/")+"/models", nil)
					if err != nil {
						continue
					}
					req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
					if acc.AccountType != "apikey" && acc.OAuthProvider != "siwc" && acc.ChatGPTAccountID != "" {
						req.Header.Set("ChatGPT-Account-ID", acc.ChatGPTAccountID)
					}
					client := &http.Client{Timeout: 10 * time.Second}
					resp, err := client.Do(req)
					if err != nil {
						m.MarkError(acc.ID, "health-check: "+err.Error())
						log.Printf("pool health-check: account %d error: %v", acc.ID, err)
						continue
					}
					resp.Body.Close()
					if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
						m.MarkError(acc.ID, "health-check: token invalid ("+http.StatusText(resp.StatusCode)+")")
						log.Printf("pool health-check: account %d invalid token (%d)", acc.ID, resp.StatusCode)
					} else if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
						log.Printf("pool health-check: account %d temporary error (%d)", acc.ID, resp.StatusCode)
					}
				}
			}
		}
	}()
}

// StartAutoReset launches a background goroutine that resets exhausted accounts
// in all pools every `interval`. Stops when ctx is cancelled.
func (m *Manager) StartAutoReset(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		log.Printf("pool: auto-reset enabled (interval: %s)", interval)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var pools []database.Pool
				if err := m.db.Find(&pools).Error; err != nil {
					log.Printf("pool auto-reset: failed to list pools: %v", err)
					continue
				}
				for _, p := range pools {
					if err := m.ResetPool(p.ID); err != nil {
						log.Printf("pool auto-reset: failed to reset pool %d: %v", p.ID, err)
					}
				}
				log.Printf("pool: auto-reset complete (%d pools)", len(pools))
			}
		}
	}()
}

// GetAccountForUser selects the best account across multiple pools.
// It picks the pool with the lowest total token usage today, then applies
// round-robin within that pool. Falls back to single-pool behaviour if only
// one pool is provided.
func (m *Manager) GetAccountForUser(poolIDs []uint) (*database.CodexAccount, error) {
	return m.GetAccountForUserExcluding(poolIDs, nil)
}

// GetAccountForUserExcluding selects the best account while skipping accounts
// already attempted for the current proxy request.
func (m *Manager) GetAccountForUserExcluding(poolIDs []uint, excluded map[uint]struct{}) (*database.CodexAccount, error) {
	if len(poolIDs) == 0 {
		return nil, ErrNoActiveAccounts
	}
	if len(poolIDs) == 1 {
		return m.GetAccountForPoolExcluding(poolIDs[0], excluded)
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	type poolUsage struct {
		id    uint
		usage int64
	}
	pools := make([]poolUsage, 0, len(poolIDs))

	for _, pid := range poolIDs {
		var usage int64
		m.db.Model(&database.UsageLog{}).
			Joins("JOIN codex_accounts ON usage_logs.account_id = codex_accounts.id").
			Joins("JOIN account_pools ON account_pools.account_id = codex_accounts.id").
			Where("account_pools.pool_id = ? AND usage_logs.created_at >= ?", pid, today).
			Select("COALESCE(SUM(usage_logs.input_tokens + usage_logs.output_tokens), 0)").
			Row().Scan(&usage)
		pools = append(pools, poolUsage{id: pid, usage: usage})
	}

	sort.Slice(pools, func(i, j int) bool { return pools[i].usage < pools[j].usage })
	for _, candidate := range pools {
		account, err := m.GetAccountForPoolExcluding(candidate.id, excluded)
		if err == nil {
			return account, nil
		}
		if !errors.Is(err, ErrNoActiveAccounts) {
			return nil, err
		}
	}

	return nil, ErrNoActiveAccounts
}

// GetAccountForPool returns the next active account for the given pool.
// Priority: active OAuth → active API keys (fallback) → exhausted OAuth (last resort).
func (m *Manager) GetAccountForPool(poolID uint) (*database.CodexAccount, error) {
	return m.GetAccountForPoolExcluding(poolID, nil)
}

// GetAccountForPoolExcluding is GetAccountForPool with a per-request exclusion
// set, used to ensure a retry actually moves to another account.
func (m *Manager) GetAccountForPoolExcluding(poolID uint, excluded map[uint]struct{}) (*database.CodexAccount, error) {
	var accounts []database.CodexAccount
	if err := m.db.Joins("JOIN account_pools ON account_pools.account_id = codex_accounts.id").
		Where("account_pools.pool_id = ? AND codex_accounts.status != ?", poolID, "error").
		Find(&accounts).Error; err != nil {
		return nil, err
	}
	accounts = filterExcluded(accounts, excluded)

	// 1. Try active OAuth accounts first (scored pick: drain mode / reset-aware)
	oauthActive := filterByTypeAndStatus(accounts, "oauth", "active")
	if len(oauthActive) > 0 {
		return m.scoredPick(oauthActive)
	}

	// 2. Fallback: try enabled API keys
	apikeys := filterByTypeAndStatus(accounts, "apikey", "active")
	if len(apikeys) > 0 {
		return m.pickAndValidate(poolID, apikeys)
	}

	// 3. Last resort: exhausted OAuth accounts (don't mark error on failure)
	oauthExhausted := filterByTypeAndStatus(accounts, "oauth", "exhausted")
	if len(oauthExhausted) > 0 {
		return m.pickAndValidateSoft(poolID, oauthExhausted)
	}

	// 4. Final fallback: error OAuth accounts (try to recover)
	var errorAccounts []database.CodexAccount
	m.db.Joins("JOIN account_pools ON account_pools.account_id = codex_accounts.id").
		Where("account_pools.pool_id = ? AND codex_accounts.status = ? AND codex_accounts.account_type = ?", poolID, "error", "oauth").
		Find(&errorAccounts)
	errorAccounts = filterExcluded(errorAccounts, excluded)
	if len(errorAccounts) > 0 {
		return m.pickAndValidateSoft(poolID, errorAccounts)
	}

	return nil, ErrNoActiveAccounts
}

func (m *Manager) pickAndValidate(poolID uint, candidates []database.CodexAccount) (*database.CodexAccount, error) {
	m.mu.Lock()
	idx := m.roundRobin[poolID] % len(candidates)
	m.roundRobin[poolID] = (idx + 1) % len(candidates)
	account := candidates[idx]
	m.mu.Unlock()

	if err := m.decryptAccount(&account); err != nil {
		return nil, err
	}

	// Skip token refresh for API keys
	if account.AccountType != "apikey" {
		if err := m.oauth.EnsureValid(m.db, &account); err != nil {
			m.MarkError(account.ID, err.Error())
			return nil, err
		}
	}

	return &account, nil
}

// pickAndValidateSoft is like pickAndValidate but doesn't mark accounts as error on failure.
// Used for last-resort exhausted accounts to avoid permanently locking out the only account.
func (m *Manager) pickAndValidateSoft(poolID uint, candidates []database.CodexAccount) (*database.CodexAccount, error) {
	m.mu.Lock()
	idx := m.roundRobin[poolID] % len(candidates)
	m.roundRobin[poolID] = (idx + 1) % len(candidates)
	account := candidates[idx]
	m.mu.Unlock()

	if err := m.decryptAccount(&account); err != nil {
		return nil, err
	}

	if account.AccountType != "apikey" {
		if err := m.oauth.EnsureValid(m.db, &account); err != nil {
			// Don't mark error — just log and return the account as-is
			// It might still work with an expired token for some endpoints
			log.Printf("pool: soft validation failed for account %d, using anyway: %v", account.ID, err)
		}
	}

	return &account, nil
}

// scoredPick selects the best OAuth account based on quota data.
// Accounts closer to their primary reset window with usage below 95% are
// prioritised so their remaining capacity is drained before the reset.
func (m *Manager) scoredPick(candidates []database.CodexAccount) (*database.CodexAccount, error) {
	type scored struct {
		account database.CodexAccount
		score   float64
	}

	var items []scored
	for _, acc := range candidates {
		var q database.AccountQuota
		score := 50.0 // default if no quota data
		if m.db.Where("account_id = ?", acc.ID).First(&q).Error == nil {
			score = q.PrimaryPct
			// Drain mode: if reset is imminent and usage below 95%, prioritize it
			if q.PrimaryResets != "" {
				if t, err := time.Parse(time.RFC3339, q.PrimaryResets); err == nil {
					minutesUntilReset := time.Until(t).Minutes()
					if minutesUntilReset > 0 && minutesUntilReset < 30 && q.PrimaryPct < 95 {
						score *= 0.2 // Heavy bonus — drain this account first
					} else if minutesUntilReset > 0 && minutesUntilReset < 60 && q.PrimaryPct < 95 {
						score *= 0.5 // Moderate bonus
					}
				}
			}
		}
		items = append(items, scored{account: acc, score: score})
	}

	// Sort by score ascending (lowest = best candidate)
	sort.Slice(items, func(i, j int) bool { return items[i].score < items[j].score })

	// Try candidates in order until one validates successfully
	for _, item := range items {
		account := item.account
		if err := m.decryptAccount(&account); err != nil {
			continue
		}
		if err := m.oauth.EnsureValid(m.db, &account); err != nil {
			m.MarkError(account.ID, err.Error())
			continue
		}
		return &account, nil
	}

	return nil, ErrNoActiveAccounts
}

func (m *Manager) MarkExhausted(accountID uint) {
	m.db.Model(&database.CodexAccount{}).
		Where("id = ?", accountID).
		Updates(map[string]interface{}{"status": "exhausted"})

	if m.webhooks != nil {
		m.webhooks.Dispatch("account.exhausted", map[string]interface{}{
			"account_id": accountID,
		})
	}
}

func (m *Manager) MarkError(accountID uint, errMsg string) {
	m.db.Model(&database.CodexAccount{}).
		Where("id = ?", accountID).
		Updates(map[string]interface{}{
			"status":     "error",
			"last_error": errMsg,
		})

	if m.webhooks != nil {
		m.webhooks.Dispatch("account.error", map[string]interface{}{
			"account_id": accountID,
			"error":      errMsg,
		})
	}
}

func (m *Manager) ResetPool(poolID uint) error {
	return m.db.Model(&database.CodexAccount{}).
		Where("id IN (SELECT account_id FROM account_pools WHERE pool_id = ?) AND status = ?", poolID, "exhausted").
		Updates(map[string]interface{}{
			"status":     "active",
			"last_error": "",
		}).Error
}

func (m *Manager) ResetAccount(accountID uint) error {
	return m.db.Model(&database.CodexAccount{}).
		Where("id = ?", accountID).
		Updates(map[string]interface{}{
			"status":     "active",
			"last_error": "",
		}).Error
}

func (m *Manager) UpdateLastUsed(accountID uint) {
	now := time.Now()
	m.db.Model(&database.CodexAccount{}).
		Where("id = ?", accountID).
		Update("last_used_at", now)
}

func (m *Manager) decryptAccount(account *database.CodexAccount) error {
	access, err := m.enc.Decrypt(account.AccessToken)
	if err != nil {
		return err
	}
	refresh, err := m.enc.Decrypt(account.RefreshToken)
	if err != nil {
		return err
	}
	account.AccessToken = access
	account.RefreshToken = refresh
	if account.IDToken != "" {
		idToken, err := m.enc.Decrypt(account.IDToken)
		if err != nil {
			return err
		}
		account.IDToken = idToken
	}
	return nil
}

func filterByStatus(accounts []database.CodexAccount, status string) []database.CodexAccount {
	var result []database.CodexAccount
	for _, a := range accounts {
		if a.Status == status {
			result = append(result, a)
		}
	}
	return result
}

func filterByTypeAndStatus(accounts []database.CodexAccount, accountType, status string) []database.CodexAccount {
	var result []database.CodexAccount
	for _, a := range accounts {
		t := a.AccountType
		if t == "" {
			t = "oauth"
		}
		if t == accountType && a.Status == status {
			result = append(result, a)
		}
	}
	return result
}

func filterExcluded(accounts []database.CodexAccount, excluded map[uint]struct{}) []database.CodexAccount {
	if len(excluded) == 0 {
		return accounts
	}
	result := make([]database.CodexAccount, 0, len(accounts))
	for _, account := range accounts {
		if _, skip := excluded[account.ID]; !skip {
			result = append(result, account)
		}
	}
	return result
}
