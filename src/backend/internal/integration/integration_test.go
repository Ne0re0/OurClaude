package integration_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"codex-proxy/internal/config"
	"codex-proxy/internal/database"
	"codex-proxy/internal/server"

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
		OpenAIAPIURL:  "http://localhost:9999/v1",
		ChatGPTURL:    "http://localhost:9999/backend-api/codex",
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

func putJSON(t *testing.T, ts *httptest.Server, path string, body interface{}, cookies []*http.Cookie) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT %s failed: %v", path, err)
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

func TestOAuthConnectPairingSession(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	poolResp := postJSON(t, ts, "/api/admin/pools", map[string]string{"name": "OAuth Pool"}, cookies)
	if poolResp.StatusCode != http.StatusCreated {
		t.Fatalf("create pool: expected 201, got %d", poolResp.StatusCode)
	}
	var pool database.Pool
	json.NewDecoder(poolResp.Body).Decode(&pool)
	poolResp.Body.Close()

	startResp := postJSON(t, ts, "/api/admin/accounts/oauth-connect", map[string]interface{}{
		"name":     "Browser login",
		"pool_ids": []uint{pool.ID},
	}, cookies)
	if startResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(startResp.Body)
		t.Fatalf("start OAuth connect: expected 201, got %d: %s", startResp.StatusCode, body)
	}
	var start struct {
		ID        uint      `json:"id"`
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	json.NewDecoder(startResp.Body).Decode(&start)
	startResp.Body.Close()
	if start.ID == 0 || !strings.HasPrefix(start.Token, "oc-connect-") || !start.ExpiresAt.After(time.Now()) {
		t.Fatalf("unexpected pairing response: %#v", start)
	}

	infoReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/oauth/connect", nil)
	infoReq.Header.Set("Authorization", "Bearer "+start.Token)
	infoResp, err := http.DefaultClient.Do(infoReq)
	if err != nil {
		t.Fatal(err)
	}
	defer infoResp.Body.Close()
	if infoResp.StatusCode != http.StatusOK {
		t.Fatalf("pairing info: expected 200, got %d", infoResp.StatusCode)
	}
	var info struct {
		HostID    string `json:"host_id"`
		AgentName string `json:"agent_name"`
	}
	json.NewDecoder(infoResp.Body).Decode(&info)
	if !strings.HasPrefix(info.HostID, "urn:uuid:") || info.AgentName != "OurCodex" {
		t.Fatalf("unexpected pairing info: %#v", info)
	}

	statusResp := getJSON(t, ts, fmt.Sprintf("/api/admin/accounts/oauth-connect/%d", start.ID), cookies)
	defer statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("pairing status: expected 200, got %d", statusResp.StatusCode)
	}
	var status struct {
		Status string `json:"status"`
	}
	json.NewDecoder(statusResp.Body).Decode(&status)
	if status.Status != "pending" {
		t.Fatalf("expected pending status, got %q", status.Status)
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
		if c.Name == "codex_proxy_session" {
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
		"name": "Alice",
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

func TestOAuthAccountPoolAssignmentOnDedupAndUpdate(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	claims, _ := json.Marshal(map[string]interface{}{
		"exp": time.Now().Add(time.Hour).Unix(),
		"https://api.openai.com/auth": map[string]interface{}{
			"chatgpt_account_id": "acct-pool-test",
		},
	})
	accessToken := "header." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
	authJSON, _ := json.Marshal(map[string]interface{}{
		"auth_mode": "chatgpt",
		"tokens": map[string]interface{}{
			"access_token":  accessToken,
			"refresh_token": "refresh-pool-test",
			"account_id":    "acct-pool-test",
		},
	})

	createAccount := postJSON(t, ts, "/api/admin/accounts", map[string]interface{}{
		"name":             "Pool account",
		"account_type":     "oauth",
		"credentials_json": string(authJSON),
	}, cookies)
	if createAccount.StatusCode != http.StatusCreated {
		t.Fatalf("initial account create: got %d", createAccount.StatusCode)
	}
	var account struct {
		ID    uint            `json:"id"`
		Pools []database.Pool `json:"pools"`
	}
	if err := json.NewDecoder(createAccount.Body).Decode(&account); err != nil {
		t.Fatal(err)
	}

	createPool := func(name string) uint {
		t.Helper()
		resp := postJSON(t, ts, "/api/admin/pools", map[string]string{"name": name}, cookies)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create pool %q: got %d", name, resp.StatusCode)
		}
		var pool database.Pool
		if err := json.NewDecoder(resp.Body).Decode(&pool); err != nil {
			t.Fatal(err)
		}
		return pool.ID
	}
	firstPoolID := createPool("First Pool")

	// Re-importing the same ChatGPT account must still apply the selected pool.
	dedup := postJSON(t, ts, "/api/admin/accounts", map[string]interface{}{
		"name":             "Pool account",
		"account_type":     "oauth",
		"credentials_json": string(authJSON),
		"pool_ids":         []uint{firstPoolID},
	}, cookies)
	if dedup.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(dedup.Body)
		t.Fatalf("deduplicated account create: got %d: %s", dedup.StatusCode, body)
	}
	if err := json.NewDecoder(dedup.Body).Decode(&account); err != nil {
		t.Fatal(err)
	}
	if len(account.Pools) != 1 || account.Pools[0].ID != firstPoolID {
		t.Fatalf("deduplicated account pools = %#v, want pool %d", account.Pools, firstPoolID)
	}

	secondPoolID := createPool("Second Pool")
	updated := putJSON(t, ts, fmt.Sprintf("/api/admin/accounts/%d", account.ID), map[string]interface{}{
		"pool_ids": []uint{secondPoolID},
	}, cookies)
	if updated.StatusCode != http.StatusOK {
		t.Fatalf("account pool update: got %d", updated.StatusCode)
	}
	if err := json.NewDecoder(updated.Body).Decode(&account); err != nil {
		t.Fatal(err)
	}
	if len(account.Pools) != 1 || account.Pools[0].ID != secondPoolID {
		t.Fatalf("updated account pools = %#v, want pool %d", account.Pools, secondPoolID)
	}

	rejected := putJSON(t, ts, fmt.Sprintf("/api/admin/accounts/%d", account.ID), map[string]interface{}{
		"pool_ids": []uint{99999},
	}, cookies)
	if rejected.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown pool update: got %d, want 400", rejected.StatusCode)
	}
}

func TestInviteFlow(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	// Create invite
	createResp := postJSON(t, ts, "/api/admin/invites", map[string]interface{}{
		"label":            "Test invite",
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
	}, nil) // no auth cookies - public endpoint
	if useResp.StatusCode != http.StatusCreated {
		t.Fatalf("use invite: expected 201, got %d", useResp.StatusCode)
	}

	var result struct {
		APIToken string `json:"api_token"`
		Name     string `json:"name"`
	}
	json.NewDecoder(useResp.Body).Decode(&result)

	if !strings.HasPrefix(result.APIToken, "sk-proxy-") {
		t.Errorf("expected sk-proxy- prefix, got %s", result.APIToken)
	}
	if result.Name != "Bob" {
		t.Errorf("expected Bob, got %s", result.Name)
	}

	// Reuse should fail
	reuse := postJSON(t, ts, "/api/invite/use", map[string]string{
		"token": invite.Token,
		"name":  "Bob2",
	}, nil)
	if reuse.StatusCode != http.StatusGone {
		t.Errorf("reuse invite: expected 410, got %d", reuse.StatusCode)
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
