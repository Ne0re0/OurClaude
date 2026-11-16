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
	mux.Handle("/auth/callback", oauthCallbackHandler(state, callbackCh))
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
		// Decoder errors name the field and JSON type, never token values.
		fmt.Fprintf(os.Stderr, "error: OpenAI returned an invalid token response: %v\n", err)
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

const callbackPageTemplate = `<!doctype html><html lang="en"><meta charset="utf-8"><title>%[1]s</title><body style="font-family:system-ui;max-width:32rem;margin:15vh auto;padding:1.5rem"><h1>%[1]s</h1><p>%[2]s</p></body></html>`

// oauthCallbackHandler handles OpenAI's loopback redirect. Only a request
// carrying this attempt's state can settle the sign-in, so stale tabs or
// unrelated local requests cannot abort a pending login. The page shown only
// sends the user back to the terminal: token exchange, verification, and the
// transfer to OurCodex happen afterwards and report their result there.
func oauthCallbackHandler(state string, results chan<- oauthCallback) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		query := r.URL.Query()
		if len(query["state"]) != 1 || subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(state)) != 1 {
			http.Error(w, "This sign-in response does not belong to the pending ourcodex login. Use the browser tab ourcodex opened.", http.StatusBadRequest)
			return
		}
		page := func(status int, title, message string) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(status)
			fmt.Fprintf(w, callbackPageTemplate, title, message)
		}
		if oauthErr := query.Get("error"); oauthErr != "" {
			page(http.StatusBadRequest, "ChatGPT sign-in was not completed", "You can close this tab. The terminal shows the reason.")
			err := fmt.Errorf("OpenAI returned %q", oauthErr)
			if description := query.Get("error_description"); description != "" {
				err = fmt.Errorf("OpenAI returned %q: %s", oauthErr, description)
			}
			sendOAuthCallback(results, oauthCallback{Err: err})
			return
		}
		code := query.Get("code")
		clientID := query.Get("client_id")
		if code == "" || len(query["code"]) != 1 || len(query["client_id"]) > 1 {
			page(http.StatusBadRequest, "ChatGPT sign-in was incomplete", "Return to the terminal and run the command again.")
			sendOAuthCallback(results, oauthCallback{Err: errors.New("OAuth callback did not contain exactly one authorization code")})
			return
		}
		if !internaloauth.ValidIssuedClientID(clientID) {
			page(http.StatusBadRequest, "ChatGPT sign-in was incomplete", "Return to the terminal and run the command again.")
			sendOAuthCallback(results, oauthCallback{Err: fmt.Errorf("OpenAI did not return an issued client ID (got %q), so registration is incomplete", clientID)})
			return
		}
		page(http.StatusOK, "Return to the terminal", "ourcodex is finishing the connection to OurCodex. You can close this tab.")
		sendOAuthCallback(results, oauthCallback{Code: code, ClientID: clientID})
	}
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
