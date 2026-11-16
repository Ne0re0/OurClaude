package quota

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"codex-proxy/internal/crypto"
	"codex-proxy/internal/database"
	"codex-proxy/internal/oauth"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const pollInterval = 3 * time.Minute

// Poller reads the same account usage endpoints as the Codex client. A read
// does not spend tokens and includes activity outside this proxy.
type Poller struct {
	db      *gorm.DB
	enc     *crypto.Encryptor
	oauth   *oauth.Refresher
	client  *http.Client
	apiURL  string
	chatURL string
	mu      sync.Mutex
}

func New(db *gorm.DB, enc *crypto.Encryptor, refresher *oauth.Refresher, apiURL, chatURL string) *Poller {
	return &Poller{
		db: db, enc: enc, oauth: refresher,
		client: &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		apiURL:  strings.TrimSuffix(strings.TrimRight(apiURL, "/"), "/v1") + "/api/codex/usage",
		chatURL: strings.TrimSuffix(strings.TrimRight(chatURL, "/"), "/codex") + "/wham/usage",
	}
}

func (p *Poller) Start(ctx context.Context) {
	go func() {
		p.pollAll(ctx)
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.pollAll(ctx)
			}
		}
	}()
}

// PollNow starts a refresh without blocking the admin HTTP request. Overlapping
// refreshes are coalesced by pollAll.
func (p *Poller) PollNow() { go p.pollAll(context.Background()) }

func (p *Poller) pollAll(ctx context.Context) {
	if !p.mu.TryLock() {
		return
	}
	defer p.mu.Unlock()
	var accounts []database.CodexAccount
	if err := p.db.Where("account_type = ?", "oauth").Find(&accounts).Error; err != nil {
		log.Printf("quota: list accounts: %v", err)
		return
	}
	for _, account := range accounts {
		if ctx.Err() != nil {
			return
		}
		if err := p.fetchOne(ctx, &account); err != nil {
			log.Printf("quota: account %d: %v", account.ID, err)
			p.recordError(account.ID, err.Error())
		}
	}
}

type usageWindow struct {
	UsedPercent        float64 `json:"used_percent"`
	LimitWindowSeconds int64   `json:"limit_window_seconds"`
	ResetAfterSeconds  int64   `json:"reset_after_seconds"`
	ResetAt            int64   `json:"reset_at"`
}

type usageResponse struct {
	PlanType  string `json:"plan_type"`
	RateLimit *struct {
		Allowed         bool         `json:"allowed"`
		LimitReached    bool         `json:"limit_reached"`
		PrimaryWindow   *usageWindow `json:"primary_window"`
		SecondaryWindow *usageWindow `json:"secondary_window"`
	} `json:"rate_limit"`
	Credits *struct {
		HasCredits bool   `json:"has_credits"`
		Unlimited  bool   `json:"unlimited"`
		Balance    string `json:"balance"`
	} `json:"credits"`
}

func (p *Poller) fetchOne(ctx context.Context, account *database.CodexAccount) error {
	access, err := p.enc.Decrypt(account.AccessToken)
	if err != nil {
		return fmt.Errorf("decrypt access token: %w", err)
	}
	refresh, err := p.enc.Decrypt(account.RefreshToken)
	if err != nil {
		return fmt.Errorf("decrypt refresh token: %w", err)
	}
	account.AccessToken, account.RefreshToken = access, refresh
	if err := p.oauth.EnsureValid(p.db, account); err != nil {
		return fmt.Errorf("refresh token: %w", err)
	}
	url := p.chatURL
	if account.OAuthProvider == "siwc" {
		url = p.apiURL
		// The public Responses API currently returns 404 for the Codex usage
		// path. The ChatGPT backend may still accept this sign-in's token.
		if strings.HasPrefix(url, "https://api.openai.com/") {
			url = p.chatURL
		}
	}
	resp, err := p.requestUsage(ctx, account, url)
	if err != nil {
		return fmt.Errorf("fetch usage: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized && account.OAuthProvider != "siwc" {
		resp.Body.Close()
		if err := p.oauth.RefreshToken(p.db, account); err != nil {
			return fmt.Errorf("usage token rejected; OAuth refresh failed: %w", err)
		}
		resp, err = p.requestUsage(ctx, account, url)
		if err != nil {
			return fmt.Errorf("fetch usage after OAuth refresh: %w", err)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if account.OAuthProvider == "siwc" && resp.StatusCode == http.StatusUnauthorized {
			return errors.New("this ChatGPT sign-in token cannot read Codex quotas; import this account's Codex auth.json credentials")
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return errors.New("Codex OAuth token rejected after refresh; sign in to Codex again and import a fresh auth.json")
		}
		return fmt.Errorf("usage endpoint returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read usage: %w", err)
	}
	var usage usageResponse
	if err := json.Unmarshal(data, &usage); err != nil {
		return fmt.Errorf("decode usage: %w", err)
	}
	if usage.PlanType == "" {
		return errors.New("usage response has no plan_type")
	}
	q := database.AccountQuota{AccountID: account.ID, Source: "usage_api", PlanType: usage.PlanType, Error: "", UpdatedAt: time.Now()}
	if usage.RateLimit != nil {
		q.Allowed = &usage.RateLimit.Allowed
		q.LimitReached = usage.RateLimit.LimitReached
		applyWindow(&q.PrimaryPct, &q.PrimaryWindowMinutes, &q.PrimaryResets, usage.RateLimit.PrimaryWindow)
		applyWindow(&q.SecondaryPct, &q.SecondaryWindowMinutes, &q.SecondaryResets, usage.RateLimit.SecondaryWindow)
	}
	if usage.Credits != nil {
		q.CreditsHas = usage.Credits.HasCredits
		q.CreditsUnlimited = usage.Credits.Unlimited
		q.CreditsBalance = usage.Credits.Balance
	}
	if err := p.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "account_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"source", "plan_type", "allowed", "limit_reached", "primary_pct", "primary_window_minutes", "primary_resets",
			"secondary_pct", "secondary_window_minutes", "secondary_resets", "credits_has", "credits_unlimited",
			"credits_balance", "error", "updated_at",
		}),
	}).Create(&q).Error; err != nil {
		return fmt.Errorf("save usage: %w", err)
	}
	// Only the backend's explicit allowance decision can recover an exhausted
	// account. A low displayed percentage alone is not proof of availability.
	if q.Allowed != nil && *q.Allowed {
		p.db.Model(&database.CodexAccount{}).Where("id = ? AND status = ?", account.ID, "exhausted").
			Updates(map[string]interface{}{"status": "active", "last_error": "", "exhausted_at": nil})
	}
	return nil
}

func (p *Poller) requestUsage(ctx context.Context, account *database.CodexAccount, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+account.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ourcodex/1.0")
	if account.OAuthProvider != "siwc" && account.ChatGPTAccountID != "" {
		req.Header.Set("ChatGPT-Account-ID", account.ChatGPTAccountID)
	}
	return p.client.Do(req)
}

func applyWindow(pct *float64, minutes **int64, resets *string, window *usageWindow) {
	if window == nil {
		return
	}
	if !math.IsNaN(window.UsedPercent) && !math.IsInf(window.UsedPercent, 0) {
		*pct = math.Max(0, math.Min(100, window.UsedPercent))
	}
	if window.LimitWindowSeconds > 0 {
		m := window.LimitWindowSeconds / 60
		*minutes = &m
	}
	if window.ResetAt > 0 {
		*resets = unixTimeString(window.ResetAt)
	} else if window.ResetAfterSeconds > 0 {
		*resets = time.Now().Add(time.Duration(window.ResetAfterSeconds) * time.Second).UTC().Format(time.RFC3339)
	}
}

func (p *Poller) recordError(accountID uint, message string) {
	// Keep the timestamp and figures of the last successful snapshot.
	var existing database.AccountQuota
	if err := p.db.Where("account_id = ?", accountID).First(&existing).Error; err == nil {
		p.db.Model(&existing).UpdateColumn("error", message)
		return
	}
	p.db.Create(&database.AccountQuota{AccountID: accountID, Error: message})
}

// UpdateFromHeaders keeps the response-header path as a fast update between
// scheduled usage reads.
func UpdateFromHeaders(db *gorm.DB, accountID uint, headers http.Header) {
	primaryPct, hasPrimary := floatHeader(headers, "x-codex-primary-used-percent")
	secondaryPct, hasSecondary := floatHeader(headers, "x-codex-secondary-used-percent")
	creditsHas, hasCredits := boolHeader(headers, "x-codex-credits-has-credits")
	if !hasPrimary && !hasSecondary && !hasCredits {
		return
	}
	primaryWindow, _ := intHeader(headers, "x-codex-primary-window-minutes")
	secondaryWindow, _ := intHeader(headers, "x-codex-secondary-window-minutes")
	primaryReset, _ := intHeader(headers, "x-codex-primary-reset-at")
	secondaryReset, _ := intHeader(headers, "x-codex-secondary-reset-at")
	creditsUnlimited, _ := boolHeader(headers, "x-codex-credits-unlimited")
	raw := map[string]string{}
	for key, values := range headers {
		if strings.HasPrefix(strings.ToLower(key), "x-codex-") && len(values) > 0 {
			raw[strings.ToLower(key)] = values[0]
		}
	}
	rawJSON, _ := json.Marshal(raw)
	q := database.AccountQuota{AccountID: accountID, Source: "response_headers", PrimaryPct: primaryPct,
		PrimaryResets: unixTimeString(primaryReset), SecondaryPct: secondaryPct,
		SecondaryResets: unixTimeString(secondaryReset), CreditsHas: creditsHas,
		CreditsUnlimited: creditsUnlimited, CreditsBalance: headers.Get("x-codex-credits-balance"),
		RawJSON: string(rawJSON), Error: "", UpdatedAt: time.Now()}
	if primaryWindow > 0 {
		q.PrimaryWindowMinutes = &primaryWindow
	}
	if secondaryWindow > 0 {
		q.SecondaryWindowMinutes = &secondaryWindow
	}
	db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "account_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"source", "primary_pct", "primary_window_minutes", "primary_resets", "secondary_pct",
			"secondary_window_minutes", "secondary_resets", "credits_has", "credits_unlimited",
			"credits_balance", "raw_json", "error", "updated_at",
		}),
	}).Create(&q)
}

func floatHeader(headers http.Header, name string) (float64, bool) {
	value := strings.TrimSpace(headers.Get(name))
	if value == "" {
		return 0, false
	}
	n, err := strconv.ParseFloat(value, 64)
	return n, err == nil
}

func intHeader(headers http.Header, name string) (int64, bool) {
	value := strings.TrimSpace(headers.Get(name))
	if value == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return n, err == nil
}

func boolHeader(headers http.Header, name string) (bool, bool) {
	value := strings.TrimSpace(headers.Get(name))
	if value == "" {
		return false, false
	}
	n, err := strconv.ParseBool(value)
	return n, err == nil
}

func unixTimeString(seconds int64) string {
	if seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}
