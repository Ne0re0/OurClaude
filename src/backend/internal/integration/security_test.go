package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func send(t *testing.T, ts *httptest.Server, method, path string, body interface{}, headers map[string]string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(payload))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s failed: %v", method, path, err)
	}
	return resp
}

func TestAdminSessionEndsOnLogoutRevokeAndPasswordChange(t *testing.T) {
	ts, _ := setupServer(t)

	// Logout: a copy of the cookie must stop working, not just the browser's.
	stolen := login(t, ts)
	if resp := getJSON(t, ts, "/api/admin/users", stolen); resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh session: expected 200, got %d", resp.StatusCode)
	}
	postJSON(t, ts, "/api/auth/logout", nil, stolen)
	if resp := getJSON(t, ts, "/api/admin/users", stolen); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("after logout: expected 401, got %d", resp.StatusCode)
	}

	// Revoke from the Sessions page.
	victimResp := send(t, ts, "POST", "/api/auth/login", map[string]string{"username": "admin", "password": "testpass123"},
		map[string]string{"User-Agent": "victim-browser"}, nil)
	victim := victimResp.Cookies()
	admin := login(t, ts)
	var sessions []struct {
		ID        uint   `json:"id"`
		UserAgent string `json:"user_agent"`
	}
	json.NewDecoder(getJSON(t, ts, "/api/admin/sessions", admin).Body).Decode(&sessions)
	var victimID uint
	for _, s := range sessions {
		if s.UserAgent == "victim-browser" {
			victimID = s.ID
		}
	}
	if victimID == 0 {
		t.Fatalf("victim session not listed: %+v", sessions)
	}
	if resp := send(t, ts, "DELETE", "/api/admin/sessions/"+strconv.FormatUint(uint64(victimID), 10), nil, nil, admin); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: expected 204, got %d", resp.StatusCode)
	}
	if resp := getJSON(t, ts, "/api/admin/users", victim); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("after revoke: expected 401, got %d", resp.StatusCode)
	}
	if resp := getJSON(t, ts, "/api/admin/users", admin); resp.StatusCode != http.StatusOK {
		t.Errorf("other session after revoke: expected 200, got %d", resp.StatusCode)
	}

	// Password change ends every session of that admin.
	other := login(t, ts)
	resp := send(t, ts, "PUT", "/api/auth/password", map[string]string{"current_password": "testpass123", "new_password": "newpass12345"}, nil, admin)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password change: expected 200, got %d", resp.StatusCode)
	}
	for name, cookies := range map[string][]*http.Cookie{"current": admin, "other": other} {
		if resp := getJSON(t, ts, "/api/admin/users", cookies); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s session after password change: expected 401, got %d", name, resp.StatusCode)
		}
	}
}

func TestLoginRateLimit(t *testing.T) {
	ts, _ := setupServer(t)

	for i := 0; i < 10; i++ {
		resp := postJSON(t, ts, "/api/auth/login", map[string]string{"username": "admin", "password": "wrong-" + strconv.Itoa(i)}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, resp.StatusCode)
		}
	}
	resp := postJSON(t, ts, "/api/auth/login", map[string]string{"username": "admin", "password": "testpass123"}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("11th attempt with the right password: expected 429, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("expected a Retry-After header")
	}
}

func TestCrossOriginAdminWritesBlocked(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)
	body := map[string]string{"name": "csrf-victim"}

	sameSite := send(t, ts, "POST", "/api/admin/users", body, map[string]string{"Sec-Fetch-Site": "same-site"}, cookies)
	if sameSite.StatusCode != http.StatusForbidden {
		t.Errorf("request from a sibling subdomain: expected 403, got %d", sameSite.StatusCode)
	}
	foreignOrigin := send(t, ts, "POST", "/api/admin/users", body, map[string]string{"Origin": "https://transfer.example.com"}, cookies)
	if foreignOrigin.StatusCode != http.StatusForbidden {
		t.Errorf("request with a foreign Origin: expected 403, got %d", foreignOrigin.StatusCode)
	}
	sameOrigin := send(t, ts, "POST", "/api/admin/users", body, map[string]string{"Sec-Fetch-Site": "same-origin"}, cookies)
	if sameOrigin.StatusCode != http.StatusCreated {
		t.Errorf("same-origin request: expected 201, got %d", sameOrigin.StatusCode)
	}
}

func TestMCPServersRequiresUserToken(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	if resp := getJSON(t, ts, "/api/user/mcp-servers", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("without a token: expected 401, got %d", resp.StatusCode)
	}

	var user struct {
		APIToken string `json:"api_token"`
	}
	json.NewDecoder(postJSON(t, ts, "/api/admin/users", map[string]string{"name": "mcp-user"}, cookies).Body).Decode(&user)
	resp := send(t, ts, "GET", "/api/user/mcp-servers", nil, map[string]string{"Authorization": "Bearer " + user.APIToken}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("with a user token: expected 200, got %d", resp.StatusCode)
	}
}

func TestImportAccountRequiresOwnPool(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	if resp := postJSON(t, ts, "/api/admin/pools", map[string]string{"name": "someone-elses-pool"}, cookies); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create pool: expected 201, got %d", resp.StatusCode)
	}
	var user struct {
		APIToken string `json:"api_token"`
	}
	json.NewDecoder(postJSON(t, ts, "/api/admin/users", map[string]string{"name": "poolless"}, cookies).Body).Decode(&user)

	creds := `{"claudeAiOauth":{"accessToken":"sk-ant-oat-test","refreshToken":"sk-ant-ort-test","expiresAt":4102444800000}}`
	resp := send(t, ts, "POST", "/api/user/import-account", map[string]string{"credentials_json": creds},
		map[string]string{"Authorization": "Bearer " + user.APIToken}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("import without a pool: expected 403, got %d", resp.StatusCode)
	}

	var accounts []json.RawMessage
	json.NewDecoder(getJSON(t, ts, "/api/admin/accounts", cookies).Body).Decode(&accounts)
	if len(accounts) != 0 {
		t.Errorf("expected no account to be created, got %d", len(accounts))
	}
}

func TestProxyOnlyForwardsMessagesAndModels(t *testing.T) {
	ts, _ := setupServer(t)
	auth := map[string]string{"Authorization": "Bearer sk-proxy-not-a-real-token"}

	for _, c := range []struct{ method, path string }{
		{"GET", "/proxy/api/oauth/profile"},
		{"DELETE", "/proxy/v1/files/file_123"},
		{"POST", "/proxy/v1/messages/batches"},
	} {
		if resp := send(t, ts, c.method, c.path, nil, auth, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: expected 404, got %d", c.method, c.path, resp.StatusCode)
		}
	}
	// Allowed routes still reach token authentication.
	if resp := send(t, ts, "POST", "/proxy/v1/messages", map[string]string{}, auth, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /proxy/v1/messages with a bad token: expected 401, got %d", resp.StatusCode)
	}
}

func TestViewerIsReadOnly(t *testing.T) {
	ts, _ := setupServer(t)
	admin := login(t, ts)
	if resp := postJSON(t, ts, "/api/admin/admins", map[string]string{"username": "watcher", "password": "watcherpass1", "role": "viewer"}, admin); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create viewer: expected 201, got %d", resp.StatusCode)
	}
	postJSON(t, ts, "/api/admin/users", map[string]string{"name": "someone"}, admin)
	viewer := postJSON(t, ts, "/api/auth/login", map[string]string{"username": "watcher", "password": "watcherpass1"}, nil).Cookies()

	var users []struct {
		APIToken string `json:"api_token"`
	}
	resp := getJSON(t, ts, "/api/admin/users", viewer)
	json.NewDecoder(resp.Body).Decode(&users)
	if resp.StatusCode != http.StatusOK || len(users) != 1 || users[0].APIToken != "" {
		t.Errorf("viewer listing users: status %d, users %+v; want 200 with API tokens hidden", resp.StatusCode, users)
	}
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/admin/users"}, {"PUT", "/api/admin/settings"}, {"GET", "/api/admin/invites"}, {"GET", "/api/admin/accounts/1/credentials"},
	} {
		if resp := send(t, ts, c.method, c.path, map[string]string{"name": "x"}, nil, viewer); resp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer %s %s: expected 403, got %d", c.method, c.path, resp.StatusCode)
		}
	}
	resp = send(t, ts, "PUT", "/api/auth/password", map[string]string{"current_password": "watcherpass1", "new_password": "watcherpass2"}, nil, viewer)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("viewer changing own password: expected 200, got %d", resp.StatusCode)
	}
}

func TestTOTPCannotBeRekeyedWhileEnabled(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	var setup struct {
		Secret string `json:"secret"`
	}
	json.NewDecoder(postJSON(t, ts, "/api/auth/totp/setup", nil, cookies).Body).Decode(&setup)
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if resp := postJSON(t, ts, "/api/auth/totp/enable", map[string]string{"code": code}, cookies); resp.StatusCode != http.StatusOK {
		t.Fatalf("enable 2FA: expected 200, got %d", resp.StatusCode)
	}
	if resp := postJSON(t, ts, "/api/auth/totp/setup", nil, cookies); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("setup while 2FA is enabled: expected 400, got %d", resp.StatusCode)
	}
}

func TestRotatingTokenRevokesSetupLinks(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	var user struct {
		ID uint `json:"id"`
	}
	json.NewDecoder(postJSON(t, ts, "/api/admin/users", map[string]string{"name": "rotator"}, cookies).Body).Decode(&user)
	id := strconv.FormatUint(uint64(user.ID), 10)
	var link struct {
		URL string `json:"url"`
	}
	json.NewDecoder(postJSON(t, ts, "/api/admin/users/"+id+"/setup-link", nil, cookies).Body).Decode(&link)
	setupToken := strings.TrimPrefix(link.URL, "/setup/")

	if resp := getJSON(t, ts, "/api/setup/"+setupToken, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("setup link before rotation: expected 200, got %d", resp.StatusCode)
	}
	postJSON(t, ts, "/api/admin/users/"+id+"/rotate-token", nil, cookies)
	if resp := getJSON(t, ts, "/api/setup/"+setupToken, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("setup link after rotation: expected 404, got %d", resp.StatusCode)
	}
}

func TestExpiredTokenRejectedOnUserAPI(t *testing.T) {
	ts, _ := setupServer(t)
	cookies := login(t, ts)

	var user struct {
		APIToken string `json:"api_token"`
	}
	json.NewDecoder(postJSON(t, ts, "/api/admin/users", map[string]string{
		"name": "expired", "token_expires_at": time.Now().Add(-time.Hour).Format(time.RFC3339),
	}, cookies).Body).Decode(&user)

	auth := map[string]string{"Authorization": "Bearer " + user.APIToken}
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/user/owned-account"}, {"POST", "/api/user/rotate-token"}, {"GET", "/api/user/mcp-servers"},
		{"POST", "/api/user/import-account"}, {"GET", "/api/user/update?platform=linux-amd64"},
	} {
		if resp := send(t, ts, c.method, c.path, nil, auth, nil); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expired token on %s %s: expected 401, got %d", c.method, c.path, resp.StatusCode)
		}
	}
	// Read-only status stays available so the CLI can report the expiry.
	if resp := send(t, ts, "GET", "/api/user/me", nil, auth, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("expired token on /api/user/me: expected 200, got %d", resp.StatusCode)
	}
}

func TestInternalEndpointsNotPublic(t *testing.T) {
	ts, _ := setupServer(t)

	for _, c := range []struct{ method, path string }{
		{"GET", "/docs"}, {"GET", "/docs/openapi.json"}, {"POST", "/api/oauth/token"},
	} {
		if resp := send(t, ts, c.method, c.path, nil, nil, nil); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without a session: expected 401, got %d", c.method, c.path, resp.StatusCode)
		}
	}
	// Through nginx (which sets X-Real-IP) metrics are hidden; a scraper on the host still gets them.
	if resp := send(t, ts, "GET", "/metrics", nil, map[string]string{"X-Real-IP": "203.0.113.9"}, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("/metrics from the internet: expected 404, got %d", resp.StatusCode)
	}
	if resp := getJSON(t, ts, "/metrics", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("/metrics from localhost: expected 200, got %d", resp.StatusCode)
	}

	resp := getJSON(t, ts, "/healthz", nil)
	if resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("security headers missing: %v", resp.Header)
	}
}

func TestSingleUseInviteCannotBeRaced(t *testing.T) {
	ts, _ := setupServerWithDB(t, filepath.Join(t.TempDir(), "race.db"))
	cookies := login(t, ts)

	var invite struct {
		Token string `json:"token"`
	}
	json.NewDecoder(postJSON(t, ts, "/api/admin/invites", map[string]interface{}{"expires_in_hours": 24}, cookies).Body).Decode(&invite)

	const parallel = 50
	statuses := make([]int, parallel)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			resp := postJSON(t, ts, "/api/invite/use", map[string]string{"token": invite.Token, "name": "racer-" + strconv.Itoa(i)}, nil)
			resp.Body.Close()
			statuses[i] = resp.StatusCode
		}(i)
	}
	close(start)
	wg.Wait()

	created := 0
	counts := map[int]int{}
	for _, s := range statuses {
		counts[s]++
		if s == http.StatusCreated {
			created++
		}
	}
	t.Logf("status counts: %v", counts)
	if created != 1 {
		t.Errorf("expected exactly 1 account from a single-use invite, got %d (statuses %v)", created, statuses)
	}

	var users []json.RawMessage
	json.NewDecoder(getJSON(t, ts, "/api/admin/users", cookies).Body).Decode(&users)
	if len(users) != 1 {
		t.Errorf("expected 1 user in the database, got %d", len(users))
	}
}
