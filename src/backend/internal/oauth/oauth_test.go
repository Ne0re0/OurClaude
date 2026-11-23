package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"claude-proxy/internal/crypto"
	"claude-proxy/internal/database"

	"gorm.io/gorm"
)

type fakeTokenServer struct {
	mu       sync.Mutex
	received []string // refresh_token values received
}

func (f *fakeTokenServer) handler(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	f.received = append(f.received, body["refresh_token"])
	n := len(f.received)
	f.mu.Unlock()
	if body["refresh_token"] != "rt-plain" && body["refresh_token"] != "rt-rotated-1" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  "at-new",
		"refresh_token": "rt-rotated-" + string(rune('0'+n)),
		"expires_in":    28800,
	})
}

func setup(t *testing.T, expiresAt time.Time) (*gorm.DB, *crypto.Encryptor, *Refresher, *fakeTokenServer, database.ClaudeAccount) {
	t.Helper()
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "t.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	enc := crypto.NewEncryptor("test-key")
	fake := &fakeTokenServer{}
	ts := httptest.NewServer(http.HandlerFunc(fake.handler))
	t.Cleanup(ts.Close)

	encA, _ := enc.Encrypt("at-old")
	encR, _ := enc.Encrypt("rt-plain")
	acc := database.ClaudeAccount{
		Name: "test", AccessToken: encA, RefreshToken: encR, RefreshTokenHash: "h",
		ExpiresAt: expiresAt, AccountType: "oauth", Status: "active",
	}
	if err := db.Create(&acc).Error; err != nil {
		t.Fatal(err)
	}
	return db, enc, New(ts.URL, enc), fake, acc
}

// decrypted mimics what pool.Manager passes to EnsureValid.
func decrypted(t *testing.T, enc *crypto.Encryptor, acc database.ClaudeAccount) database.ClaudeAccount {
	t.Helper()
	a, err := enc.Decrypt(acc.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	r, err := enc.Decrypt(acc.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	acc.AccessToken, acc.RefreshToken = a, r
	return acc
}

func TestEnsureValidSendsPlaintextRefreshToken(t *testing.T) {
	db, enc, r, fake, acc := setup(t, time.Now().Add(-time.Hour))
	a := decrypted(t, enc, acc)

	if err := r.EnsureValid(db, &a); err != nil {
		t.Fatalf("EnsureValid: %v", err)
	}
	if len(fake.received) != 1 || fake.received[0] != "rt-plain" {
		t.Fatalf("token endpoint received %q, want plaintext refresh token", fake.received)
	}
	if a.AccessToken != "at-new" || a.RefreshToken != "rt-rotated-1" {
		t.Fatalf("in-memory account not updated with decrypted tokens: %q / %q", a.AccessToken, a.RefreshToken)
	}

	var stored database.ClaudeAccount
	db.First(&stored, acc.ID)
	got := decrypted(t, enc, stored)
	if got.AccessToken != "at-new" || got.RefreshToken != "rt-rotated-1" {
		t.Fatalf("DB not updated: %q / %q", got.AccessToken, got.RefreshToken)
	}
	if time.Until(stored.ExpiresAt) < 7*time.Hour {
		t.Fatalf("expiry not extended: %v", stored.ExpiresAt)
	}
}

// When another goroutine already refreshed, EnsureValid must still hand back
// decrypted (not encrypted) tokens.
func TestEnsureValidAfterConcurrentRefreshReturnsDecrypted(t *testing.T) {
	db, enc, r, fake, acc := setup(t, time.Now().Add(-time.Hour))
	stale := decrypted(t, enc, acc)

	db.Model(&database.ClaudeAccount{}).Where("id = ?", acc.ID).Update("expires_at", time.Now().Add(8*time.Hour))

	if err := r.EnsureValid(db, &stale); err != nil {
		t.Fatalf("EnsureValid: %v", err)
	}
	if len(fake.received) != 0 {
		t.Fatalf("unexpected refresh call")
	}
	if stale.AccessToken != "at-old" {
		t.Fatalf("got %q, want decrypted access token", stale.AccessToken)
	}
}

func TestBackgroundRefreshOnlyRefreshesExpiringAccounts(t *testing.T) {
	db, enc, r, fake, soon := setup(t, time.Now().Add(10*time.Minute))

	encA, _ := enc.Encrypt("at-other")
	encR, _ := enc.Encrypt("rt-other")
	later := database.ClaudeAccount{Name: "later", AccessToken: encA, RefreshToken: encR, RefreshTokenHash: "h2",
		ExpiresAt: time.Now().Add(5 * time.Hour), AccountType: "oauth", Status: "active"}
	db.Create(&later)
	encK, _ := enc.Encrypt("sk-ant-key")
	encE, _ := enc.Encrypt("")
	apikey := database.ClaudeAccount{Name: "key", AccessToken: encK, RefreshToken: encE, RefreshTokenHash: "h3",
		AccountType: "apikey", Status: "active"}
	db.Create(&apikey)

	r.refreshExpiring(db)

	if len(fake.received) != 1 || fake.received[0] != "rt-plain" {
		t.Fatalf("token endpoint received %q, want exactly the expiring account", fake.received)
	}
	var stored database.ClaudeAccount
	db.First(&stored, soon.ID)
	if time.Until(stored.ExpiresAt) < 7*time.Hour {
		t.Fatalf("expiring account not refreshed: %v", stored.ExpiresAt)
	}
}

func TestBackgroundRefreshBacksOffAndKeepsExhaustedStatus(t *testing.T) {
	db, enc, r, fake, acc := setup(t, time.Now().Add(-time.Hour))
	bad, _ := enc.Encrypt("rt-revoked")
	db.Model(&database.ClaudeAccount{}).Where("id = ?", acc.ID).Updates(map[string]interface{}{"refresh_token": bad, "status": "exhausted"})

	r.refreshExpiring(db)
	r.refreshExpiring(db) // within backoff: must not call again
	if len(fake.received) != 1 {
		t.Fatalf("expected 1 attempt during backoff, got %d", len(fake.received))
	}

	// Fix the token, clear backoff, refresh again: status must stay exhausted.
	good, _ := enc.Encrypt("rt-plain")
	db.Model(&database.ClaudeAccount{}).Where("id = ?", acc.ID).Update("refresh_token", good)
	r.recordSuccess(acc.ID)
	r.refreshExpiring(db)

	var stored database.ClaudeAccount
	db.First(&stored, acc.ID)
	if stored.Status != "exhausted" {
		t.Fatalf("status = %q, want exhausted preserved", stored.Status)
	}
	if time.Until(stored.ExpiresAt) < 7*time.Hour {
		t.Fatalf("not refreshed after fixing token")
	}
}
