package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"codex-proxy/internal/crypto"
	"codex-proxy/internal/database"
	"codex-proxy/internal/oauth"
	"codex-proxy/internal/pool"
	"codex-proxy/internal/webhook"

	"gorm.io/gorm"
)

type stubSettings struct{}

func (stubSettings) Get(string) string   { return "" }
func (stubSettings) GetBool(string) bool { return false }
func (stubSettings) GetInt(string) int   { return 0 }

// fakePlanUpstream imitates the ChatGPT plan route: every response is SSE
// served as text/plain. respond picks the stream for each request.
type fakePlanUpstream struct {
	mu        sync.Mutex
	tokens    []string
	encodings []string
	respond   func(call int) string
}

func (f *fakePlanUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.tokens = append(f.tokens, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	f.encodings = append(f.encodings, r.Header.Get("Accept-Encoding"))
	body := f.respond(len(f.tokens))
	f.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, body)
}

func (f *fakePlanUpstream) setResponder(respond func(call int) string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens, f.encodings, f.respond = nil, nil, respond
}

func (f *fakePlanUpstream) calls() (tokens, encodings []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.tokens...), append([]string(nil), f.encodings...)
}

func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func accountStatus(db *gorm.DB, token string) string {
	var account database.CodexAccount
	db.Where("name = ?", token).First(&account)
	return account.Status
}

func TestServeHTTPRecordsUsageAndFailsOverOnPlanLimits(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "proxy.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	enc := crypto.NewEncryptor("test-encryption-key")
	manager := pool.New(db, oauth.New("http://127.0.0.1:1/token", "client", enc), enc, webhook.New(db))

	upstream := &fakePlanUpstream{}
	server := httptest.NewServer(upstream)
	defer server.Close()

	poolRecord := database.Pool{Name: "plan accounts"}
	db.Create(&poolRecord)
	user := database.User{Name: "dev", APIToken: "sk-proxy-test", Active: true}
	db.Create(&user)
	db.Create(&database.UserPool{UserID: user.ID, PoolID: poolRecord.ID})
	for _, token := range []string{"token-a", "token-b"} {
		access, _ := enc.Encrypt(token)
		refresh, _ := enc.Encrypt("refresh-" + token)
		account := database.CodexAccount{
			Name: token, AccessToken: access, RefreshToken: refresh,
			AccountType: "oauth", OAuthProvider: "siwc", OAuthClientID: "oaiapp_test",
			Status: "active", ExpiresAt: time.Now().Add(time.Hour),
		}
		db.Create(&account)
		db.Create(&database.AccountPool{AccountID: account.ID, PoolID: poolRecord.ID})
	}

	newHandler := func() *Handler {
		return New(db, manager, server.URL+"/v1", server.URL+"/backend-api/codex", "", stubSettings{}, nil, nil, nil)
	}
	h := newHandler()
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/proxy/v1/responses",
			strings.NewReader(`{"model":"gpt-6-luna","stream":true,"store":false,"input":[]}`))
		req.Header.Set("Authorization", "Bearer sk-proxy-test")
		req.Header.Set("Accept-Encoding", "gzip, br, zstd") // what Codex may negotiate
		recorder := httptest.NewRecorder()
		h.ServeHTTP(recorder, req)
		return recorder
	}

	// 1. The first account reaches its plan limit as soon as the stream opens:
	// the client must transparently get the second account's response.
	upstream.setResponder(func(call int) string {
		if call == 1 {
			return limitedStream
		}
		return completedStream
	})
	resp := send()
	if resp.Code != http.StatusOK || resp.Body.String() != completedStream {
		t.Fatalf("status %d, body %q", resp.Code, resp.Body.String())
	}
	tokens, encodings := upstream.calls()
	if len(tokens) != 2 || tokens[0] == tokens[1] {
		t.Fatalf("expected failover to a second account, upstream saw %v", tokens)
	}
	for _, encoding := range encodings {
		if encoding != "identity" {
			t.Fatalf("client encoding leaked upstream: %v", encodings)
		}
	}
	limited, healthy := tokens[0], tokens[1]
	if status := accountStatus(db, limited); status != "exhausted" {
		t.Fatalf("limited account status = %q, want exhausted", status)
	}

	// Usage from the text/plain stream is what token quotas and budgets sum.
	var usage database.UsageLog
	eventually(t, "usage to be recorded", func() bool {
		return db.Where("input_tokens > 0").First(&usage).Error == nil
	})
	if usage.Model != "gpt-6-luna" || usage.InputTokens != 23 || usage.OutputTokens != 5 || usage.CacheRead != 4 {
		t.Fatalf("unexpected usage log: %+v", usage)
	}

	// With usage recorded, the user's token quota and budget now apply. A new
	// handler starts with an empty quota cache.
	for _, limit := range []struct {
		column string
		value  interface{}
		want   string
	}{
		{"daily_token_quota", 20, "daily token quota exceeded"},
		{"monthly_budget_usd", 0.000001, "monthly budget"},
	} {
		db.Model(&database.User{}).Where("id = ?", user.ID).Update(limit.column, limit.value)
		h = newHandler()
		if resp := send(); resp.Code != http.StatusTooManyRequests || !strings.Contains(resp.Body.String(), limit.want) {
			t.Fatalf("%s not enforced: %d %s", limit.column, resp.Code, resp.Body.String())
		}
		db.Model(&database.User{}).Where("id = ?", user.ID).Update(limit.column, 0)
	}
	h = newHandler()

	// 2. A completed response brings the exhausted account back into rotation.
	db.Model(&database.CodexAccount{}).Where("name = ?", healthy).Update("status", "disabled")
	upstream.setResponder(func(int) string { return completedStream })
	if resp := send(); resp.Code != http.StatusOK {
		t.Fatalf("recovery request status %d: %s", resp.Code, resp.Body.String())
	}
	eventually(t, "exhausted account to recover", func() bool { return accountStatus(db, limited) == "active" })

	// 3. A limit hit after output has streamed cannot be retried, but the
	// account is taken out of rotation for the next request.
	upstream.setResponder(func(int) string { return lateLimitStream })
	if resp := send(); resp.Code != http.StatusOK || resp.Body.String() != lateLimitStream {
		t.Fatalf("late-limit response altered: %d %q", resp.Code, resp.Body.String())
	}
	eventually(t, "mid-stream limit to exhaust the account", func() bool { return accountStatus(db, limited) == "exhausted" })

	// 4. When every account is at its limit, the client is told to back off.
	db.Model(&database.CodexAccount{}).Where("name = ?", healthy).Update("status", "active")
	upstream.setResponder(func(int) string { return limitedStream })
	resp = send()
	if resp.Code != http.StatusTooManyRequests || !strings.Contains(resp.Body.String(), "usage limit") {
		t.Fatalf("all-limited response: %d %s", resp.Code, resp.Body.String())
	}
}
