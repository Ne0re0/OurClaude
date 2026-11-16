package quota

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"codex-proxy/internal/crypto"
	"codex-proxy/internal/database"
	"codex-proxy/internal/oauth"
)

func TestUpdateFromHeaders(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "quota.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	reset := time.Now().Add(time.Hour).Unix()
	headers := http.Header{
		"X-Codex-Primary-Used-Percent":     []string{"37.5"},
		"X-Codex-Primary-Window-Minutes":   []string{"300"},
		"X-Codex-Primary-Reset-At":         []string{strconv.FormatInt(reset, 10)},
		"X-Codex-Secondary-Used-Percent":   []string{"12"},
		"X-Codex-Secondary-Window-Minutes": []string{"10080"},
		"X-Codex-Credits-Has-Credits":      []string{"true"},
		"X-Codex-Credits-Balance":          []string{"42.00"},
	}
	UpdateFromHeaders(db, 9, headers)

	var got database.AccountQuota
	if err := db.Where("account_id = ?", 9).First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.PrimaryPct != 37.5 || got.PrimaryWindowMinutes == nil || *got.PrimaryWindowMinutes != 300 {
		t.Fatalf("unexpected primary quota: %#v", got)
	}
	if got.SecondaryPct != 12 || !got.CreditsHas || got.CreditsBalance != "42.00" {
		t.Fatalf("unexpected quota: %#v", got)
	}
}

func TestPollerFetchesBothOAuthUsageRoutes(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "quota.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	enc := crypto.NewEncryptor("test-key")
	access, _ := enc.Encrypt("account-access")
	refresh, _ := enc.Encrypt("account-refresh")
	reset := time.Now().Add(time.Hour).Unix()
	requests := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.Path + ":" + r.Header.Get("ChatGPT-Account-ID")
		if r.Header.Get("Authorization") != "Bearer account-access" {
			t.Errorf("missing account bearer token")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"plan_type": "plus",
			"rate_limit": map[string]interface{}{
				"allowed": true, "limit_reached": false,
				"primary_window":   map[string]interface{}{"used_percent": 35, "limit_window_seconds": 18000, "reset_at": reset},
				"secondary_window": map[string]interface{}{"used_percent": 60, "limit_window_seconds": 604800, "reset_at": reset},
			},
			"credits": map[string]interface{}{"has_credits": true, "unlimited": false, "balance": "12.50"},
		})
	}))
	defer upstream.Close()
	poller := New(db, enc, oauth.New(upstream.URL, "test-client", enc), upstream.URL+"/v1", upstream.URL+"/backend-api/codex")
	for _, provider := range []string{"codex", "siwc"} {
		account := database.CodexAccount{
			Name: provider, AccountType: "oauth", OAuthProvider: provider,
			AccessToken: access, RefreshToken: refresh, ExpiresAt: time.Now().Add(time.Hour),
			ChatGPTAccountID: "chat-account", Status: "exhausted",
		}
		if err := db.Create(&account).Error; err != nil {
			t.Fatal(err)
		}
		if err := poller.fetchOne(context.Background(), &account); err != nil {
			t.Fatalf("%s usage: %v", provider, err)
		}
		var got database.AccountQuota
		if err := db.Where("account_id = ?", account.ID).First(&got).Error; err != nil {
			t.Fatal(err)
		}
		if got.Source != "usage_api" || got.PlanType != "plus" || got.Allowed == nil || !*got.Allowed ||
			got.PrimaryPct != 35 || got.SecondaryPct != 60 || got.PrimaryWindowMinutes == nil || *got.PrimaryWindowMinutes != 300 ||
			got.CreditsBalance != "12.50" || got.PrimaryResets == "" {
			t.Fatalf("%s quota: %+v", provider, got)
		}
		var saved database.CodexAccount
		db.First(&saved, account.ID)
		if saved.Status != "active" {
			t.Fatalf("%s did not recover after backend allowed usage", provider)
		}
	}
	if got := <-requests; got != "/backend-api/wham/usage:chat-account" {
		t.Fatalf("legacy request: %s", got)
	}
	if got := <-requests; got != "/api/codex/usage:" {
		t.Fatalf("SIWC request: %s", got)
	}
}

func TestPollerFailurePreservesLastSnapshot(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "quota.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	updated := time.Now().Add(-time.Hour).Truncate(time.Second)
	q := database.AccountQuota{AccountID: 7, Source: "usage_api", PrimaryPct: 72, UpdatedAt: updated}
	db.Create(&q)
	p := &Poller{db: db}
	p.recordError(7, "usage endpoint returned HTTP 403")
	var got database.AccountQuota
	db.Where("account_id = ?", 7).First(&got)
	if got.PrimaryPct != 72 || !got.UpdatedAt.Equal(updated) || got.Error == "" {
		t.Fatalf("snapshot changed on failure: %+v", got)
	}
}

func TestPollerRefreshesRejectedLegacyToken(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "quota.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	enc := crypto.NewEncryptor("test-key")
	access, _ := enc.Encrypt("revoked-access")
	refresh, _ := enc.Encrypt("valid-refresh")
	var usageCalls, refreshCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backend-api/wham/usage":
			usageCalls++
			if r.Header.Get("Authorization") == "Bearer revoked-access" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Header.Get("Authorization") != "Bearer fresh-access" {
				t.Errorf("unexpected bearer token on retry")
			}
			w.Write([]byte(`{"plan_type":"plus","rate_limit":{"allowed":true,"primary_window":{"used_percent":25,"limit_window_seconds":18000}}}`))
		case "/oauth/token":
			refreshCalls++
			w.Write([]byte(`{"access_token":"fresh-access","refresh_token":"fresh-refresh","expires_in":3600}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()
	account := database.CodexAccount{
		Name: "legacy", AccountType: "oauth", OAuthProvider: "codex", Status: "active",
		AccessToken: access, RefreshToken: refresh, ExpiresAt: time.Now().Add(time.Hour),
		ChatGPTAccountID: "chat-account", OAuthIssuer: upstream.URL,
	}
	db.Create(&account)
	p := New(db, enc, oauth.New(upstream.URL+"/oauth/token", "test-client", enc), upstream.URL+"/v1", upstream.URL+"/backend-api/codex")
	if err := p.fetchOne(context.Background(), &account); err != nil {
		t.Fatal(err)
	}
	if usageCalls != 2 || refreshCalls != 1 {
		t.Fatalf("got %d usage calls and %d refresh calls", usageCalls, refreshCalls)
	}
	var saved database.CodexAccount
	db.First(&saved, account.ID)
	got, err := enc.Decrypt(saved.AccessToken)
	if err != nil || got != "fresh-access" {
		t.Fatalf("refreshed access token was not persisted: %v", err)
	}
	var quota database.AccountQuota
	db.Where("account_id = ?", account.ID).First(&quota)
	if quota.PrimaryPct != 25 || quota.Source != "usage_api" {
		t.Fatalf("quota not saved after refresh: %+v", quota)
	}
}
