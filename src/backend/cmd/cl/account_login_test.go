package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func callbackRequest(t *testing.T, handler http.Handler, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/callback?"+query.Encode(), nil))
	return recorder
}

func TestOAuthCallbackHandlerAcceptsIssuedClient(t *testing.T) {
	// The documented new-registration callback, including the optional scope.
	for _, clientID := range []string{"oaiapp_EHBV7pzdMtehZ7j6Ypgyje-F", "agentclient_123"} {
		results := make(chan oauthCallback, 1)
		handler := oauthCallbackHandler("expected-state", results)
		recorder := callbackRequest(t, handler, url.Values{
			"code":      {"auth-code"},
			"scope":     {"chatgpt.tokens.use.direct email offline_access openid profile resource.invoke"},
			"state":     {"expected-state"},
			"client_id": {clientID},
		})
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", clientID, recorder.Code, recorder.Body)
		}
		if strings.Contains(recorder.Body.String(), "connected") {
			t.Errorf("%s: page claims success before the terminal finished: %s", clientID, recorder.Body)
		}
		got := <-results
		if got.Err != nil || got.Code != "auth-code" || got.ClientID != clientID {
			t.Fatalf("%s: unexpected callback result: %#v", clientID, got)
		}
	}
}

func TestOAuthCallbackHandlerIgnoresForeignState(t *testing.T) {
	results := make(chan oauthCallback, 1)
	handler := oauthCallbackHandler("expected-state", results)
	for _, query := range []url.Values{
		{"code": {"c"}, "state": {"stale-state"}, "client_id": {"oaiapp_x"}},
		{"code": {"c"}, "client_id": {"oaiapp_x"}},
		{"code": {"c"}, "state": {"expected-state", "expected-state"}, "client_id": {"oaiapp_x"}},
	} {
		if recorder := callbackRequest(t, handler, query); recorder.Code != http.StatusBadRequest {
			t.Fatalf("state %v: status %d", query["state"], recorder.Code)
		}
	}
	select {
	case got := <-results:
		t.Fatalf("an unrelated request settled the pending login: %#v", got)
	default:
	}

	// The genuine redirect still completes afterwards.
	callbackRequest(t, handler, url.Values{"code": {"c"}, "state": {"expected-state"}, "client_id": {"oaiapp_x"}})
	if got := <-results; got.Err != nil || got.ClientID != "oaiapp_x" {
		t.Fatalf("unexpected callback result: %#v", got)
	}
}

func TestOAuthCallbackHandlerFailures(t *testing.T) {
	cases := map[string]url.Values{
		"denied":                   {"error": {"access_denied"}, "state": {"s"}},
		"missing code":             {"state": {"s"}, "client_id": {"oaiapp_x"}},
		"missing client ID":        {"code": {"c"}, "state": {"s"}},
		"registration placeholder": {"code": {"c"}, "state": {"s"}, "client_id": {"dynamic_agent_client"}},
		"duplicate client ID":      {"code": {"c"}, "state": {"s"}, "client_id": {"oaiapp_x", "oaiapp_y"}},
	}
	for name, query := range cases {
		results := make(chan oauthCallback, 1)
		recorder := callbackRequest(t, oauthCallbackHandler("s", results), query)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, recorder.Code)
		}
		if got := <-results; got.Err == nil {
			t.Errorf("%s: expected an error, got %#v", name, got)
		}
	}
}
