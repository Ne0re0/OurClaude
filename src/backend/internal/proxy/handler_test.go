package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"codex-proxy/internal/database"
)

func TestForwardRoutesResponsesByAccountType(t *testing.T) {
	type observed struct {
		path      string
		auth      string
		accountID string
		body      string
		headers   http.Header
	}
	requests := make(chan observed, 3)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- observed{
			path:      r.URL.RequestURI(),
			auth:      r.Header.Get("Authorization"),
			accountID: r.Header.Get("ChatGPT-Account-ID"),
			body:      string(body),
			headers:   r.Header.Clone(),
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_test"}`))
	}))
	defer upstream.Close()

	h := &Handler{
		apiUpstream:     upstream.URL + "/v1",
		chatGPTUpstream: upstream.URL + "/backend-api/codex",
		client:          upstream.Client(),
	}
	user := &database.User{}

	for _, test := range []struct {
		name        string
		account     database.CodexAccount
		wantPath    string
		wantAccount string
	}{
		{
			name:        "chatgpt oauth",
			account:     database.CodexAccount{AccountType: "oauth", AccessToken: "oauth-token", ChatGPTAccountID: "acct-123"},
			wantPath:    "/backend-api/codex/responses?stream=true",
			wantAccount: "acct-123",
		},
		{
			name:     "api key",
			account:  database.CodexAccount{AccountType: "apikey", AccessToken: "sk-test"},
			wantPath: "/v1/responses?stream=true",
		},
		{
			name:     "sign in with chatgpt",
			account:  database.CodexAccount{AccountType: "oauth", OAuthProvider: "siwc", AccessToken: "siwc-token", ChatGPTAccountID: "must-not-be-sent"},
			wantPath: "/v1/responses?stream=true",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://ourcodex.test/proxy/v1/responses?stream=true", strings.NewReader(`{"model":"gpt-test"}`))
			req.Header.Set("CF-Connecting-IP", "203.0.113.1")
			req.Header.Set("CF-Ray", "test-ray")
			req.Header.Set("X-Forwarded-For", "203.0.113.1")
			req.Header.Set("X-Real-IP", "203.0.113.1")
			req.Header.Set("OpenAI-Beta", "responses=experimental")
			resp, err := h.forward(req, []byte(`{"model":"gpt-test"}`), &test.account, user)
			if err != nil {
				t.Fatalf("forward: %v", err)
			}
			resp.Body.Close()

			got := <-requests
			if got.path != test.wantPath {
				t.Errorf("path = %q, want %q", got.path, test.wantPath)
			}
			if got.auth != "Bearer "+test.account.AccessToken {
				t.Errorf("Authorization = %q", got.auth)
			}
			if got.accountID != test.wantAccount {
				t.Errorf("ChatGPT-Account-ID = %q, want %q", got.accountID, test.wantAccount)
			}
			for _, key := range []string{"CF-Connecting-IP", "CF-Ray", "X-Forwarded-For", "X-Real-IP"} {
				if got.headers.Get(key) != "" {
					t.Errorf("upstream received %s", key)
				}
			}
			if got.headers.Get("OpenAI-Beta") != "responses=experimental" {
				t.Errorf("OpenAI-Beta was not forwarded")
			}
		})
	}
}

func TestInjectSystemPromptUsesResponsesInstructions(t *testing.T) {
	got := string(injectSystemPrompt([]byte(`{"model":"gpt-test","instructions":"existing","input":"hi"}`), "managed"))
	if !strings.Contains(got, `"instructions":"managed\n\nexisting"`) {
		t.Fatalf("unexpected request: %s", got)
	}
	if strings.Contains(got, `"system"`) {
		t.Fatalf("Messages API system field was injected: %s", got)
	}
}

func TestParseResponsesUsage(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "usage.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{
		"model":"gpt-test",
		"usage":{"input_tokens":20,"output_tokens":7,"input_tokens_details":{"cached_tokens":5}},
		"output":[{"type":"message","content":[{"type":"output_text","text":"hello"}]}]
	}`)
	parseAndLogUsage(body, false, 1, 2, "/responses", 200, 12, 0, `"prompt"`, db, nil, nil)

	var log database.UsageLog
	if err := db.First(&log).Error; err != nil {
		t.Fatal(err)
	}
	if log.Model != "gpt-test" || log.InputTokens != 20 || log.OutputTokens != 7 || log.CacheRead != 5 {
		t.Fatalf("unexpected usage log: %#v", log)
	}
	var conversation database.ConversationLog
	if err := db.First(&conversation).Error; err != nil {
		t.Fatal(err)
	}
	if conversation.ResponseText != "hello" {
		t.Fatalf("response text = %q", conversation.ResponseText)
	}
}
