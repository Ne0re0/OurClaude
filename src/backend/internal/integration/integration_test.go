package integration_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"claude-proxy/internal/config"
	"claude-proxy/internal/database"
	"claude-proxy/internal/server"

	"golang.org/x/crypto/bcrypt"
)

// setupServer creates an in-memory test server with SQLite :memory: DB.
func setupServer(t *testing.T) (*httptest.Server, *config.Config) {
	t.Helper()

	cfg := &config.Config{
		WebPort:       "0",
		JWTSecret:     "test-secret-1234567890",
		JWTExpiry:     1 * time.Hour,
		DBType:        "sqlite",
		DBPath:        ":memory:",
		AnthropicURL:  "http://localhost:9999",
		EncryptionKey: "test-enc-key-12345",
	}

	db, err := database.New(cfg.DBType, cfg.DBPath, "")
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}

	// Seed admin
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass123"), bcrypt.MinCost)
	db.Create(&database.Admin{
		Username:     "admin",
		PasswordHash: string(hash),
		Role:         "super_admin",
	})

	srv := server.New(cfg, db, nil)
	ts := httptest.NewServer(srv.SetupAdminRouter())
	t.Cleanup(ts.Close)

	return ts, cfg
}

func postJSON(t *testing.T, ts *httptest.Server, path string, body interface{}, cookies []*http.Cookie) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s failed: %v", path, err)
	}
	return resp
}

func getJSON(t *testing.T, ts *httptest.Server, path string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	return resp
}

func login(t *testing.T, ts *httptest.Server) []*http.Cookie {
	t.Helper()
	resp := postJSON(t, ts, "/api/auth/login", map[string]string{
		"username": "admin",
		"password": "testpass123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %d", resp.StatusCode)
	}
	return resp.Cookies()
}

// --- Tests ---

func TestHealthCheck(t *testing.T) {
	ts, _ := setupServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestLogin_Success(t *testing.T) {
	ts, _ := setupServer(t)
	resp := postJSON(t, ts, "/api/auth/login", map[string]string{
		"username": "admin",
		"password": "testpass123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	hasCookie := false
	for _, c := range resp.Cookies() {
		if c.Name == "claude_proxy_session" {
			hasCookie = true
		}
	}
	if !hasCookie {
		t.Error("expected session cookie")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	ts, _ := setupServer(t)
	resp := postJSON(t, ts, "/api/auth/login", map[string]string{
		"username": "admin",
		"password": "wrong",
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestMe_Authenticated(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)
	resp := getJSON(t, ts, "/api/auth/me", cookies)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestMe_Unauthenticated(t *testing.T) {
	ts, _ := setupServer(t)
	resp := getJSON(t, ts, "/api/auth/me", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestUserCRUD(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	// Create pool first
	poolResp := postJSON(t, ts, "/api/admin/pools", map[string]string{
		"name": "Test Pool",
	}, cookies)
	if poolResp.StatusCode != http.StatusCreated {
		t.Fatalf("create pool: expected 201, got %d", poolResp.StatusCode)
	}

	// Create user
	resp := postJSON(t, ts, "/api/admin/users", map[string]interface{}{
		"name":  "Alice",
		"email": "alice@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user: expected 201, got %d", resp.StatusCode)
	}

	var user struct {
		ID       int    `json:"id"`
		APIToken string `json:"api_token"`
	}
	json.NewDecoder(resp.Body).Decode(&user)

	if !strings.HasPrefix(user.APIToken, "sk-proxy-") {
		t.Errorf("expected sk-proxy- prefix, got %s", user.APIToken)
	}

	// List users
	listResp := getJSON(t, ts, "/api/admin/users", cookies)
	if listResp.StatusCode != http.StatusOK {
		t.Errorf("list users: expected 200, got %d", listResp.StatusCode)
	}

	// Duplicate email
	dup := postJSON(t, ts, "/api/admin/users", map[string]interface{}{
		"name":  "Alice2",
		"email": "alice@example.com",
	}, cookies)
	if dup.StatusCode != http.StatusConflict {
		t.Errorf("duplicate email: expected 409, got %d", dup.StatusCode)
	}
}

func TestPoolCRUD(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	resp := postJSON(t, ts, "/api/admin/pools", map[string]string{
		"name":        "Main Pool",
		"description": "Primary account pool",
	}, cookies)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create pool: expected 201, got %d", resp.StatusCode)
	}

	listResp := getJSON(t, ts, "/api/admin/pools", cookies)
	if listResp.StatusCode != http.StatusOK {
		t.Errorf("list pools: expected 200, got %d", listResp.StatusCode)
	}
}

func TestInviteFlow(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	// Create invite
	createResp := postJSON(t, ts, "/api/admin/invites", map[string]interface{}{
		"label":           "Test invite",
		"expires_in_hours": 24,
	}, cookies)
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create invite: expected 201, got %d", createResp.StatusCode)
	}

	var invite struct {
		Token string `json:"token"`
	}
	json.NewDecoder(createResp.Body).Decode(&invite)

	if invite.Token == "" {
		t.Fatal("expected non-empty token")
	}

	// Use invite
	useResp := postJSON(t, ts, "/api/invite/use", map[string]string{
		"token": invite.Token,
		"name":  "Bob",
		"email": "bob@example.com",
	}, nil) // no auth cookies - public endpoint
	if useResp.StatusCode != http.StatusCreated {
		t.Fatalf("use invite: expected 201, got %d", useResp.StatusCode)
	}

	var result struct {
		APIToken string `json:"api_token"`
		Email    string `json:"email"`
	}
	json.NewDecoder(useResp.Body).Decode(&result)

	if !strings.HasPrefix(result.APIToken, "sk-proxy-") {
		t.Errorf("expected sk-proxy- prefix, got %s", result.APIToken)
	}
	if result.Email != "bob@example.com" {
		t.Errorf("expected bob@example.com, got %s", result.Email)
	}

	// Reuse should fail
	reuse := postJSON(t, ts, "/api/invite/use", map[string]string{
		"token": invite.Token,
		"name":  "Bob2",
		"email": "bob2@example.com",
	}, nil)
	if reuse.StatusCode != http.StatusGone {
		t.Errorf("reuse invite: expected 410, got %d", reuse.StatusCode)
	}
}

func TestMultiUseInvite(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	createResp := postJSON(t, ts, "/api/admin/invites", map[string]interface{}{
		"label":            "Team invite",
		"expires_in_hours": 24,
		"multi_use":        true,
	}, cookies)
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create invite: expected 201, got %d", createResp.StatusCode)
	}
	var invite struct {
		Token string `json:"token"`
	}
	json.NewDecoder(createResp.Body).Decode(&invite)

	tokens := map[string]bool{}
	for _, name := range []string{"Alice", "Bob"} {
		resp := postJSON(t, ts, "/api/invite/use", map[string]string{"token": invite.Token, "name": name}, nil)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("use invite as %s: expected 201, got %d", name, resp.StatusCode)
		}
		var result struct {
			APIToken string `json:"api_token"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		tokens[result.APIToken] = true
	}
	if len(tokens) != 2 {
		t.Errorf("expected 2 distinct API tokens, got %d", len(tokens))
	}

	listResp := getJSON(t, ts, "/api/admin/invites", cookies)
	var invites []struct {
		MultiUse bool    `json:"multi_use"`
		UseCount int     `json:"use_count"`
		UsedAt   *string `json:"used_at"`
	}
	json.NewDecoder(listResp.Body).Decode(&invites)
	if len(invites) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(invites))
	}
	if !invites[0].MultiUse || invites[0].UseCount != 2 || invites[0].UsedAt != nil {
		t.Errorf("expected active multi-use invite with use_count=2, got %+v", invites[0])
	}
}

func TestInviteUseLeadsToAutoSetup(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	createResp := postJSON(t, ts, "/api/admin/invites", map[string]interface{}{"expires_in_hours": 24}, cookies)
	var invite struct {
		Token string `json:"token"`
	}
	json.NewDecoder(createResp.Body).Decode(&invite)

	useResp := postJSON(t, ts, "/api/invite/use", map[string]string{"token": invite.Token, "name": "Carol"}, nil)
	if useResp.StatusCode != http.StatusCreated {
		t.Fatalf("use invite: expected 201, got %d", useResp.StatusCode)
	}
	var result struct {
		APIToken string `json:"api_token"`
		SetupURL string `json:"setup_url"`
	}
	json.NewDecoder(useResp.Body).Decode(&result)
	setupToken, ok := strings.CutPrefix(result.SetupURL, "/setup/")
	if !ok || setupToken == "" {
		t.Fatalf("expected setup_url like /setup/<token>, got %q", result.SetupURL)
	}

	setupResp := getJSON(t, ts, "/api/setup/"+setupToken, nil)
	if setupResp.StatusCode != http.StatusOK {
		t.Fatalf("setup page data: expected 200, got %d", setupResp.StatusCode)
	}
	var setup struct {
		Name     string `json:"name"`
		APIToken string `json:"api_token"`
	}
	json.NewDecoder(setupResp.Body).Decode(&setup)
	if setup.Name != "Carol" || setup.APIToken != result.APIToken {
		t.Errorf("setup page returned %+v, want Carol with the invite's API token", setup)
	}

	scriptResp := getJSON(t, ts, "/api/install/"+setupToken, nil)
	script, _ := io.ReadAll(scriptResp.Body)
	if scriptResp.StatusCode != http.StatusOK || !strings.Contains(string(script), result.APIToken) {
		t.Errorf("install script: expected 200 embedding the API token, got %d", scriptResp.StatusCode)
	}
}

func TestUserSelfService(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	// Create a user
	createResp := postJSON(t, ts, "/api/admin/users", map[string]interface{}{
		"name":  "Carol",
		"email": "carol@example.com",
	}, cookies)
	var user struct {
		APIToken string `json:"api_token"`
	}
	json.NewDecoder(createResp.Body).Decode(&user)

	// Hit /api/user/me with user token
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/user/me", nil)
	req.Header.Set("Authorization", "Bearer "+user.APIToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("self /me: expected 200, got %d", resp.StatusCode)
	}
}

func TestWebhookCRUD(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	resp := postJSON(t, ts, "/api/admin/webhooks", map[string]string{
		"url":    "https://example.com/hook",
		"events": "account.exhausted,account.error",
		"secret": "mysecret",
	}, cookies)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create webhook: expected 201, got %d", resp.StatusCode)
	}

	listResp := getJSON(t, ts, "/api/admin/webhooks", cookies)
	if listResp.StatusCode != http.StatusOK {
		t.Errorf("list webhooks: expected 200, got %d", listResp.StatusCode)
	}
}

func TestTokenExpiry(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	// Create user with already-expired token
	past := time.Now().Add(-1 * time.Hour)
	createResp := postJSON(t, ts, "/api/admin/users", map[string]interface{}{
		"name":             "Dave",
		"email":            "dave@example.com",
		"token_expires_at": past.Format(time.RFC3339),
	}, cookies)
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create user: %d", createResp.StatusCode)
	}
	var user struct {
		APIToken string `json:"api_token"`
	}
	json.NewDecoder(createResp.Body).Decode(&user)

	// Self-service should still work (expiry only enforced on proxy)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/user/me", nil)
	req.Header.Set("Authorization", "Bearer "+user.APIToken)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("self /me with expired token: expected 200 (expiry only on proxy), got %d", resp.StatusCode)
	}
}

func TestAuditLog(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	// Trigger an auditable action
	postJSON(t, ts, "/api/admin/users", map[string]interface{}{
		"name":  "Eve",
		"email": "eve@example.com",
	}, cookies)

	// Check audit log
	resp := getJSON(t, ts, "/api/admin/audit", cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit log: expected 200, got %d", resp.StatusCode)
	}

	var result struct {
		Total int `json:"total"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if result.Total < 1 {
		t.Errorf("expected at least 1 audit entry, got %d", result.Total)
	}
}

func TestStatsExportCSV(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	resp := getJSON(t, ts, "/api/admin/stats/export", cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export CSV: expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("expected text/csv, got %s", ct)
	}
}

func TestPoolAddAccounts(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	decode := func(resp *http.Response, v interface{}) {
		t.Helper()
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	type idOnly struct {
		ID uint `json:"id"`
	}

	var poolA, poolB idOnly
	decode(postJSON(t, ts, "/api/admin/pools", map[string]string{"name": "A"}, cookies), &poolA)
	decode(postJSON(t, ts, "/api/admin/pools", map[string]string{"name": "B"}, cookies), &poolB)

	creds := `{"claudeAiOauth":{"accessToken":"at-test","refreshToken":"rt-test","expiresAt":4102444800000}}`
	resp := postJSON(t, ts, "/api/admin/accounts", map[string]interface{}{
		"name":             "acc1",
		"credentials_json": creds,
		"pool_ids":         []uint{poolA.ID, poolB.ID},
	}, cookies)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create account: expected 201, got %d", resp.StatusCode)
	}
	var acc idOnly
	decode(resp, &acc)

	// Remove the account from pool A only.
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/admin/accounts/"+itoa(acc.ID)+"/pool?pool_id="+itoa(poolA.ID), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("unlink: expected 204, got %d", delResp.StatusCode)
	}

	// Add it back to pool A.
	type addResult struct {
		Added int64 `json:"added"`
		Pool  struct {
			Accounts []idOnly `json:"accounts"`
		} `json:"pool"`
	}
	resp = postJSON(t, ts, "/api/admin/pools/"+itoa(poolA.ID)+"/accounts", map[string]interface{}{"account_ids": []uint{acc.ID}}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add accounts: expected 200, got %d", resp.StatusCode)
	}
	var res addResult
	decode(resp, &res)
	if res.Added != 1 || len(res.Pool.Accounts) != 1 || res.Pool.Accounts[0].ID != acc.ID {
		t.Fatalf("add accounts: unexpected result %+v", res)
	}

	// The account must be in both pools again (pool B link untouched).
	var got struct {
		Pools []idOnly `json:"pools"`
	}
	decode(getJSON(t, ts, "/api/admin/accounts/"+itoa(acc.ID), cookies), &got)
	if len(got.Pools) != 2 {
		t.Fatalf("expected account in 2 pools, got %+v", got.Pools)
	}

	// Adding again is a no-op, not an error.
	resp = postJSON(t, ts, "/api/admin/pools/"+itoa(poolA.ID)+"/accounts", map[string]interface{}{"account_ids": []uint{acc.ID}}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-add: expected 200, got %d", resp.StatusCode)
	}
	decode(resp, &res)
	if res.Added != 0 || len(res.Pool.Accounts) != 1 {
		t.Fatalf("re-add: unexpected result %+v", res)
	}

	// Bad input.
	if r := postJSON(t, ts, "/api/admin/pools/"+itoa(poolA.ID)+"/accounts", map[string]interface{}{"account_ids": []uint{}}, cookies); r.StatusCode != http.StatusBadRequest {
		t.Errorf("empty ids: expected 400, got %d", r.StatusCode)
	}
	if r := postJSON(t, ts, "/api/admin/pools/"+itoa(poolA.ID)+"/accounts", map[string]interface{}{"account_ids": []uint{99999}}, cookies); r.StatusCode != http.StatusNotFound {
		t.Errorf("unknown account: expected 404, got %d", r.StatusCode)
	}
	if r := postJSON(t, ts, "/api/admin/pools/99999/accounts", map[string]interface{}{"account_ids": []uint{acc.ID}}, cookies); r.StatusCode != http.StatusNotFound {
		t.Errorf("unknown pool: expected 404, got %d", r.StatusCode)
	}
}

func itoa(n uint) string { return strconv.FormatUint(uint64(n), 10) }
