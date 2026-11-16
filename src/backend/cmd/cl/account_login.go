package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	internaloauth "codex-proxy/internal/oauth"

	"golang.org/x/term"
)

type oauthConnectInfo struct {
	HostID    string    `json:"host_id"`
	AgentName string    `json:"agent_name"`
	ExpiresAt time.Time `json:"expires_at"`
}

type oauthCallback struct {
	Code     string
	ClientID string
	Err      error
}

// cmdAccountLogin completes OpenAI's supported loopback OAuth flow locally,
// then transfers the verified credential set to a one-time server pairing
// session. Tokens never pass through browser JavaScript or command arguments.
func cmdAccountLogin(args []string) {
	if len(args) < 1 || len(args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: ourcodex account-login <server_url> [pairing_token]")
		fmt.Fprintln(os.Stderr, "Create a pairing command from Accounts > Add OAuth Account in the dashboard.")
		os.Exit(1)
	}
	serverURL := strings.TrimRight(args[0], "/")
	parsed, err := url.Parse(serverURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		fmt.Fprintln(os.Stderr, "error: invalid server URL")
		os.Exit(1)
	}
	if parsed.Scheme != "https" && !isLoopbackHost(parsed.Hostname()) {
		fmt.Fprintln(os.Stderr, "error: account login requires HTTPS (except for a local server)")
		os.Exit(1)
	}

	pairingToken := ""
	if len(args) == 2 {
		pairingToken = strings.TrimSpace(args[1])
	} else {
		fmt.Print("Pairing token: ")
		if term.IsTerminal(int(os.Stdin.Fd())) {
			raw, readErr := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if readErr != nil {
				fmt.Fprintf(os.Stderr, "error reading pairing token: %v\n", readErr)
				os.Exit(1)
			}
			pairingToken = strings.TrimSpace(string(raw))
		} else {
			raw, _ := io.ReadAll(io.LimitReader(os.Stdin, 4096))
			pairingToken = strings.TrimSpace(string(raw))
		}
	}
	if !strings.HasPrefix(pairingToken, "oc-connect-") {
		fmt.Fprintln(os.Stderr, "error: invalid pairing token")
		os.Exit(1)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	var info oauthConnectInfo
	if err := connectJSON(client, http.MethodGet, serverURL+"/api/oauth/connect", pairingToken, nil, &info); err != nil {
		fmt.Fprintf(os.Stderr, "error: pairing failed: %v\n", err)
		os.Exit(1)
	}
	if info.HostID == "" || info.AgentName == "" || time.Now().After(info.ExpiresAt) {
		fmt.Fprintln(os.Stderr, "error: pairing session is incomplete or expired")
		os.Exit(1)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot start local OAuth callback: %v\n", err)
		os.Exit(1)
	}
	redirectURI := "http://127.0.0.1:" + fmt.Sprint(listener.Addr().(*net.TCPAddr).Port) + "/auth/callback"
	state, err := randomOAuthValue(32)
	if err != nil {
		listener.Close()
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	nonce, err := randomOAuthValue(32)
	if err != nil {
		listener.Close()
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	verifier, err := randomOAuthValue(64)
	if err != nil {
		listener.Close()
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])

	callbackCh := make(chan oauthCallback, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		returnedState := r.URL.Query().Get("state")
		if subtle.ConstantTimeCompare([]byte(returnedState), []byte(state)) != 1 {
			http.Error(w, "Sign-in could not be verified. Return to the terminal and try again.", http.StatusBadRequest)
			sendOAuthCallback(callbackCh, oauthCallback{Err: errors.New("OAuth state did not match")})
			return
		}
		if oauthErr := r.URL.Query().Get("error"); oauthErr != "" {
			description := r.URL.Query().Get("error_description")
			http.Error(w, "ChatGPT sign-in was cancelled. You can close this tab.", http.StatusBadRequest)
			sendOAuthCallback(callbackCh, oauthCallback{Err: fmt.Errorf("%s: %s", oauthErr, description)})
			return
		}
		code := r.URL.Query().Get("code")
		clientID := r.URL.Query().Get("client_id")
		if code == "" || !strings.HasPrefix(clientID, "oaiapp_") {
			http.Error(w, "ChatGPT sign-in returned an incomplete response.", http.StatusBadRequest)
			sendOAuthCallback(callbackCh, oauthCallback{Err: errors.New("OAuth callback was incomplete")})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><html><body style="font-family:system-ui;padding:3rem"><h1>ChatGPT connected</h1><p>You can close this tab and return to the terminal.</p></body></html>`)
		sendOAuthCallback(callbackCh, oauthCallback{Code: code, ClientID: clientID})
	})
	callbackServer := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if serveErr := callbackServer.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			sendOAuthCallback(callbackCh, oauthCallback{Err: serveErr})
		}
	}()

	authorizeURL, _ := url.Parse(internaloauth.SIWCAuthorizeURL)
	params := authorizeURL.Query()
	params.Set("client_id", internaloauth.SIWCDynamicClientID)
	params.Set("agent_name_hint", info.AgentName)
	params.Set("ext_agent_host_id", info.HostID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", internaloauth.SIWCRegistrationScope)
	params.Set("resource", internaloauth.SIWCResource)
	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("code_challenge_method", "S256")
	params.Set("code_challenge", challenge)
	authorizeURL.RawQuery = params.Encode()

	fmt.Println("Opening ChatGPT in your browser...")
	if err := openSystemBrowser(authorizeURL.String()); err != nil {
		fmt.Fprintln(os.Stderr, "Could not open a browser automatically. Open this URL on this computer:")
	}
	fmt.Println(authorizeURL.String())
	fmt.Println("Waiting for ChatGPT authorization (up to 15 minutes)...")

	wait := time.Until(info.ExpiresAt)
	if wait > 15*time.Minute || wait <= 0 {
		wait = 15 * time.Minute
	}
	var callback oauthCallback
	select {
	case callback = <-callbackCh:
	case <-time.After(wait):
		callback.Err = errors.New("pairing session expired")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = callbackServer.Shutdown(shutdownCtx)
	cancel()
	if callback.Err != nil {
		fmt.Fprintf(os.Stderr, "error: ChatGPT sign-in failed: %v\n", callback.Err)
		os.Exit(1)
	}

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {callback.ClientID},
		"code":          {callback.Code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
		"resource":      {internaloauth.SIWCResource},
	}
	tokenReq, _ := http.NewRequest(http.MethodPost, internaloauth.SIWCTokenURL, strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Accept", "application/json")
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: token exchange failed: %v\n", err)
		os.Exit(1)
	}
	tokenBody, _ := io.ReadAll(io.LimitReader(tokenResp.Body, 1<<20))
	tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "error: token exchange failed (HTTP %d): %s\n", tokenResp.StatusCode, safeOAuthError(tokenBody))
		os.Exit(1)
	}
	var tokens internaloauth.SIWCTokenResponse
	if err := json.Unmarshal(tokenBody, &tokens); err != nil {
		fmt.Fprintln(os.Stderr, "error: OpenAI returned an invalid token response")
		os.Exit(1)
	}
	identity, err := internaloauth.VerifySIWCCredentials(context.Background(), client, tokens, callback.ClientID, nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not verify ChatGPT credentials: %v\n", err)
		os.Exit(1)
	}

	completeBody := map[string]interface{}{"client_id": callback.ClientID, "tokens": tokens}
	var result struct {
		AccountID uint   `json:"account_id"`
		Message   string `json:"message"`
	}
	if err := connectJSON(client, http.MethodPost, serverURL+"/api/oauth/connect", pairingToken, completeBody, &result); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not transfer credentials to OurCodex: %v\n", err)
		os.Exit(1)
	}
	display := identity.Email
	if display == "" {
		display = identity.Name
	}
	if display != "" {
		fmt.Printf("Connected %s to OurCodex (account %d).\n", display, result.AccountID)
	} else {
		fmt.Printf("ChatGPT account connected to OurCodex (account %d).\n", result.AccountID)
	}
}

func connectJSON(client *http.Client, method, endpoint, token string, body interface{}, out interface{}) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &apiErr) == nil && apiErr.Error != "" {
			return errors.New(apiErr.Error)
		}
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func randomOAuthValue(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func sendOAuthCallback(ch chan<- oauthCallback, result oauthCallback) {
	select {
	case ch <- result:
	default:
	}
}

func openSystemBrowser(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", target)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
}

func safeOAuthError(data []byte) string {
	var response struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(data, &response) == nil {
		if response.ErrorDescription != "" {
			return response.Error + ": " + response.ErrorDescription
		}
		if response.Error != "" {
			return response.Error
		}
	}
	return "OpenAI rejected the request"
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
