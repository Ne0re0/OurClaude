package handlers

import (
	"path/filepath"
	"testing"
	"time"

	"claude-proxy/internal/crypto"
	"claude-proxy/internal/database"
)

func TestNormalizeSubscriptionLevel(t *testing.T) {
	got, err := normalizeSubscriptionLevel(" Ultra ")
	if err != nil || got != "ultra" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := normalizeSubscriptionLevel("<script>"); err == nil {
		t.Fatal("expected invalid level")
	}
}

func TestQuotaFiveHourAvailable(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{`{"five_hour":{"utilization":20}}`, true},
		{`{"five_hour":null}`, false},
		{`{}`, false},
	} {
		got := quotaFiveHourAvailable(database.AccountQuota{RawJSON: tc.raw})
		if got != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestImportedSubscriptionLevelSurvivesTokenUpdate(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "accounts.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	h := &AccountsHandler{db: db, enc: crypto.NewEncryptor("test-key")}
	account, _, err := h.upsertOAuthAccount("test", "access-1", "refresh", time.Now().Add(time.Hour), "Ultra", nil)
	if err != nil {
		t.Fatal(err)
	}
	if account.SubscriptionLevel != "ultra" {
		t.Fatalf("got %q", account.SubscriptionLevel)
	}
	_, updated, err := h.upsertOAuthAccount("test", "access-2", "refresh", time.Now().Add(time.Hour), "", nil)
	if err != nil || !updated {
		t.Fatalf("update failed: %v", err)
	}
	var saved database.ClaudeAccount
	if err := db.First(&saved, account.ID).Error; err != nil {
		t.Fatal(err)
	}
	if saved.SubscriptionLevel != "ultra" {
		t.Fatalf("update erased tier: %q", saved.SubscriptionLevel)
	}
}
