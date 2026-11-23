package pool

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"claude-proxy/internal/crypto"
	"claude-proxy/internal/database"
	"claude-proxy/internal/oauth"
)

func newSelectionTestManager(t *testing.T, quotas ...int) (*Manager, uint, []database.ClaudeAccount) {
	t.Helper()
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "selection.db"), "")
	if err != nil {
		t.Fatalf("create database: %v", err)
	}
	enc := crypto.NewEncryptor("selection-test-key")
	accessToken, err := enc.Encrypt("sk-ant-oat-test")
	if err != nil {
		t.Fatalf("encrypt access token: %v", err)
	}
	refreshToken, err := enc.Encrypt("refresh-test")
	if err != nil {
		t.Fatalf("encrypt refresh token: %v", err)
	}
	poolRecord := database.Pool{Name: "selection-test"}
	if err := db.Create(&poolRecord).Error; err != nil {
		t.Fatalf("create pool: %v", err)
	}
	accounts := make([]database.ClaudeAccount, 0, len(quotas))
	for i, quota := range quotas {
		account := database.ClaudeAccount{
			Name: fmt.Sprintf("account-%d", i+1), AccessToken: accessToken,
			RefreshToken: refreshToken, RefreshTokenHash: fmt.Sprintf("refresh-hash-%d", i+1),
			ExpiresAt: time.Now().Add(time.Hour), AccountType: "oauth", Status: "active",
		}
		if err := db.Create(&account).Error; err != nil {
			t.Fatalf("create account: %v", err)
		}
		if err := db.Create(&database.AccountPool{AccountID: account.ID, PoolID: poolRecord.ID}).Error; err != nil {
			t.Fatalf("link account to pool: %v", err)
		}
		reset := time.Now().Add(3 * time.Hour)
		if quota == 100 {
			reset = time.Now().Add(30 * time.Minute)
		}
		if err := db.Create(&database.AccountQuota{AccountID: account.ID, FiveHourPct: quota, FiveHourAvailable: true, FiveHourResets: reset.Format(time.RFC3339)}).Error; err != nil {
			t.Fatalf("create account quota: %v", err)
		}
		accounts = append(accounts, account)
	}
	return New(db, oauth.New("http://unused.invalid", enc), enc, nil), poolRecord.ID, accounts
}

func TestSelectionDoesNotFavorFullAccountNearReset(t *testing.T) {
	manager, poolID, accounts := newSelectionTestManager(t, 100, 51)
	selected, err := manager.GetAccountForUser([]uint{poolID})
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if selected.ID != accounts[1].ID {
		t.Fatalf("selected account %d at 100%%, want account %d at 51%%", selected.ID, accounts[1].ID)
	}
}

func TestSelectionExcludesPreviouslyAttemptedAccount(t *testing.T) {
	manager, poolID, accounts := newSelectionTestManager(t, 10, 20)
	selected, err := manager.GetAccountForUserExcluding([]uint{poolID}, map[uint]struct{}{accounts[0].ID: {}})
	if err != nil {
		t.Fatalf("select account: %v", err)
	}
	if selected.ID != accounts[1].ID {
		t.Fatalf("selected excluded account %d, want account %d", selected.ID, accounts[1].ID)
	}
}
