package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

// binaryToken is patched by the server when this binary is downloaded.
// The sentinel "OCBINTOK:" followed by 32 hex chars is replaced with a unique key.
var binaryToken = "OCBINTOK:00000000000000000000000000000000"

const configFile = ".ourcodex/config.json"
const codexCredsFile = ".codex/auth.json"

type Config struct {
	ServerURL string `json:"server_url"`
	Token     string `json:"token"`
}

// codexCredentials mirrors the stable fields in ~/.codex/auth.json while
// preserving unknown fields when credentials are refreshed by the proxy.
type codexCredentials struct {
	AuthMode string `json:"auth_mode"`
	Tokens   struct {
		IDToken         string `json:"id_token"`
		AccessToken     string `json:"access_token"`
		RefreshToken    string `json:"refresh_token"`
		AccountID       string `json:"account_id"`
		LoginOwnerID    string `json:"login_owner_id"`
		OAuthProvenance struct {
			Issuer   string `json:"issuer"`
			ClientID string `json:"client_id"`
		} `json:"oauth_provenance"`
	} `json:"tokens"`
	LastRefresh string `json:"last_refresh"`
}

func configPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: cannot find home directory")
		os.Exit(1)
	}
	return filepath.Join(home, configFile)
}

func codexCredsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, codexCredsFile)
}

func loadConfig() (*Config, error) {
	data, err := os.ReadFile(configPath())
	// If not found and running as sudo, try the real user's home
	if err != nil && os.IsNotExist(err) {
		if home := sudoUserHome(); home != "" {
			altPath := filepath.Join(home, configFile)
			data, err = os.ReadFile(altPath)
		}
	}
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("malformed config: %w", err)
	}
	return &cfg, nil
}

func saveConfig(cfg *Config) error {
	path := configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// readLocalCreds reads ~/.codex/auth.json and returns nil if not found or invalid.
func readLocalCreds() *codexCredentials {
	path := codexCredsPath()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var creds codexCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil
	}
	if creds.Tokens.AccessToken == "" || creds.Tokens.RefreshToken == "" {
		return nil
	}
	return &creds
}

// mergeLocalCreds updates Codex OAuth fields while preserving future fields.
func mergeLocalCreds(remote *codexCredentials) error {
	path := codexCredsPath()
	if path == "" {
		return fmt.Errorf("cannot determine home directory")
	}

	// Read existing file as a generic map to preserve unknown fields
	existing := map[string]interface{}{}
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, &existing) //nolint:errcheck
	}

	tokens, _ := existing["tokens"].(map[string]interface{})
	if tokens == nil {
		tokens = map[string]interface{}{}
	}
	tokens["access_token"] = remote.Tokens.AccessToken
	tokens["refresh_token"] = remote.Tokens.RefreshToken
	if remote.Tokens.IDToken != "" {
		tokens["id_token"] = remote.Tokens.IDToken
	}
	if remote.Tokens.AccountID != "" {
		tokens["account_id"] = remote.Tokens.AccountID
	}
	if remote.Tokens.LoginOwnerID != "" {
		tokens["login_owner_id"] = remote.Tokens.LoginOwnerID
	}
	if remote.Tokens.OAuthProvenance.Issuer != "" || remote.Tokens.OAuthProvenance.ClientID != "" {
		tokens["oauth_provenance"] = remote.Tokens.OAuthProvenance
	}
	existing["tokens"] = tokens
	if remote.AuthMode != "" {
		existing["auth_mode"] = remote.AuthMode
	}
	if remote.LastRefresh != "" {
		existing["last_refresh"] = remote.LastRefresh
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func proxyHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func main() {
	// Always sync credentials if logged in (silent, best-effort)
	if cfg, err := loadConfig(); err == nil {
		syncOwnedAccount(cfg)
	}

	args := os.Args[1:]

	if len(args) == 0 {
		runCodex(nil)
		return
	}

	switch args[0] {
	case "login":
		cmdLogin(args[1:])
	case "init":
		cmdInit(args[1:])
	case "logout":
		cmdLogout()
	case "status":
		cmdStatus()
	case "usage":
		cmdUsage()
	case "update":
		cmdUpdate()
	case "uninstall":
		cmdUninstall()
	case "mcp-sync":
		cmdMCPSync()
	case "help", "--help", "-h":
		printHelp()
	default:
		runCodex(args)
	}
}

// ourcodex login <server_url> [token]
func cmdLogin(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ourcodex login <server_url> [token] [--auto-share]")
		fmt.Fprintln(os.Stderr, "example: ourcodex login http://proxy.example.com:8080")
		os.Exit(1)
	}

	// Parse --auto-share flag
	autoShare := false
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--auto-share" {
			autoShare = true
		} else {
			filtered = append(filtered, a)
		}
	}
	args = filtered

	serverURL := strings.TrimRight(args[0], "/")

	if _, err := url.Parse(serverURL); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid server URL: %v\n", err)
		os.Exit(1)
	}

	var token string

	if len(args) >= 2 {
		token = args[1]
	} else {
		fmt.Printf("Server: %s\n", serverURL)
		fmt.Print("Paste your API token (sk-proxy-...): ")

		if term.IsTerminal(int(os.Stdin.Fd())) {
			raw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading token: %v\n", err)
				os.Exit(1)
			}
			token = strings.TrimSpace(string(raw))
		} else {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			token = strings.TrimSpace(scanner.Text())
		}
	}

	if token == "" {
		fmt.Fprintln(os.Stderr, "error: token cannot be empty")
		os.Exit(1)
	}

	if !strings.HasPrefix(token, "sk-proxy-") {
		fmt.Fprintln(os.Stderr, "warning: token doesn't look like a proxy token (expected sk-proxy-...)")
	}

	// Verify token with server before saving
	verifyReq, err := http.NewRequest("GET", serverURL+"/api/user/me", nil)
	if err == nil {
		verifyReq.Header.Set("Authorization", "Bearer "+token)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(verifyReq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not reach server: %v\n", err)
		} else {
			resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				fmt.Fprintln(os.Stderr, "error: token rejected by server — check that the token is correct")
				os.Exit(1)
			}
			if resp.StatusCode == http.StatusOK {
				fmt.Println("Token verified with server.")
			}
		}
	}

	cfg := &Config{
		ServerURL: serverURL,
		Token:     token,
	}

	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error saving config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Logged in to %s\n", serverURL)
	fmt.Printf("  Config saved to ~/%s\n", configFile)

	offerCredentialImport(serverURL, token, autoShare)
}

// ourcodex init <server_url> [token]
// Like login, but also detects a local Codex account and offers to share it with the proxy.
func cmdInit(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ourcodex init <server_url> [token]")
		fmt.Fprintln(os.Stderr, "example: ourcodex init http://proxy.example.com:8080")
		os.Exit(1)
	}

	serverURL := strings.TrimRight(args[0], "/")
	if _, err := url.Parse(serverURL); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid server URL: %v\n", err)
		os.Exit(1)
	}

	var token string
	if len(args) >= 2 {
		token = args[1]
	} else {
		fmt.Printf("Server: %s\n", serverURL)
		fmt.Print("Paste your API token (sk-proxy-...): ")
		if term.IsTerminal(int(os.Stdin.Fd())) {
			raw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading token: %v\n", err)
				os.Exit(1)
			}
			token = strings.TrimSpace(string(raw))
		} else {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			token = strings.TrimSpace(scanner.Text())
		}
	}

	if token == "" {
		fmt.Fprintln(os.Stderr, "error: token cannot be empty")
		os.Exit(1)
	}

	cfg := &Config{ServerURL: serverURL, Token: token}
	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error saving config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Logged in to %s\n", serverURL)

	offerCredentialImport(serverURL, token, true) // init always auto-shares
}

// offerCredentialImport detects a local Codex account and offers to share it with the proxy.
// Called by both cmdLogin and cmdInit after saving the config.
func offerCredentialImport(serverURL, token string, autoShare bool) {
	creds := readLocalCreds()
	if creds == nil {
		fmt.Printf("\nNo Codex account found in ~/%s.\n", codexCredsFile)
		fmt.Printf("If you have a Codex account, log in with the Codex CLI first, then re-run 'ourcodex login'.\n")
		fmt.Printf("\nYou can now use: ourcodex <codex-args>\n")
		return
	}

	// Show what was found (truncated for privacy)
	accessPreview := creds.Tokens.AccessToken
	if len(accessPreview) > 20 {
		accessPreview = accessPreview[:12] + "..." + accessPreview[len(accessPreview)-4:]
	}
	fmt.Printf("\nFound Codex account in ~/%s\n", codexCredsFile)
	fmt.Printf("  Access token:  %s\n", accessPreview)
	if creds.Tokens.AccountID != "" {
		fmt.Printf("  Account ID:    %s\n", creds.Tokens.AccountID)
	}

	if autoShare {
		fmt.Println("\nSharing Codex account with proxy (auto-share enabled)...")
	} else {
		fmt.Printf("\nShare this Codex account with the proxy? [y/N] ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if answer != "y" && answer != "yes" {
			fmt.Println("Skipped. You can run 'ourcodex login --auto-share' to share later.")
			fmt.Printf("\nYou can now use: ourcodex <codex-args>\n")
			return
		}
	}

	credsJSON, err := json.Marshal(creds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to marshal credentials: %v\n", err)
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]string{"credentials_json": string(credsJSON)})
	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/user/import-account", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to import account: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var errMsg struct {
			Error string `json:"error"`
		}
		json.Unmarshal(respBody, &errMsg)
		msg := errMsg.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		fmt.Fprintf(os.Stderr, "error importing account: %s\n", msg)
		os.Exit(1)
	}

	var result struct {
		Message   string `json:"message"`
		AccountID uint   `json:"account_id"`
	}
	json.Unmarshal(respBody, &result)

	action := "imported"
	if resp.StatusCode == http.StatusOK {
		action = "updated"
	}
	fmt.Printf("Account %s (id: %d). The proxy will keep your local credentials in sync.\n", action, result.AccountID)
	fmt.Printf("\nYou can now use: ourcodex <codex-args>\n")
}

func cmdLogout() {
	path := configPath()
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Not logged in.")
		} else {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	fmt.Printf("Logged out (removed ~/%s)\n", configFile)
}

func cmdUninstall() {
	fmt.Println("Uninstalling ourcodex...")

	// Delete owned account on the server (best-effort)
	if cfg, err := loadConfig(); err == nil {
		req, err := http.NewRequest("DELETE", cfg.ServerURL+"/api/user/owned-account", nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+cfg.Token)
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					fmt.Println("  Removed owned account from proxy")
				}
			}
		}
	}

	// Remove config (own home + sudo user's home if running as root)
	cfgPath := configPath()
	if err := os.Remove(cfgPath); err == nil {
		fmt.Printf("  Removed %s\n", cfgPath)
	}
	if home := sudoUserHome(); home != "" {
		altCfg := filepath.Join(home, configFile)
		if err := os.Remove(altCfg); err == nil {
			fmt.Printf("  Removed %s\n", altCfg)
		}
	}

	// Remove binary from known locations
	self, _ := os.Executable()
	locations := []string{
		"/usr/local/bin/ourcodex",
		"/usr/bin/ourcodex",
	}
	if self != "" {
		locations = append([]string{self}, locations...)
	}

	removed := false
	needSudo := false
	for _, path := range locations {
		if _, err := os.Stat(path); err == nil {
			if err := os.Remove(path); err != nil {
				needSudo = true
			} else {
				fmt.Printf("  Removed %s\n", path)
				removed = true
			}
		}
	}
	if needSudo {
		fmt.Fprintln(os.Stderr, "\n  Insufficient permissions. Run: sudo ourcodex uninstall")
		os.Exit(1)
	}

	if !removed {
		fmt.Println("  Binary not found in standard locations — remove it manually.")
	}

	fmt.Println("Done. ourcodex has been uninstalled.")
}

func cmdStatus() {
	cfg, err := loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Not logged in. Run: ourcodex login <server_url>")
		} else {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	masked := cfg.Token
	if len(masked) > 12 {
		masked = masked[:12] + "..." + masked[len(masked)-4:]
	}

	fmt.Printf("Server:  %s\n", cfg.ServerURL)
	fmt.Printf("Token:   %s\n", masked)
	fmt.Printf("Config:  ~/%s\n", configFile)
	fmt.Printf("Provider: OurCodex (%s/proxy/v1)\n", cfg.ServerURL)
	fmt.Printf("\nEnvironment passed to Codex:\n")
	fmt.Printf("  OURCODEX_API_KEY=%s\n", masked)
	host := proxyHost(cfg.ServerURL)
	if host != "" {
		fmt.Printf("  NO_PROXY=%s\n", host)
	}

	// Show owned account sync status.
	creds := readLocalCreds()
	if creds != nil {
		fmt.Printf("\nOwned account: synced")
		if creds.Tokens.AccountID != "" {
			fmt.Printf(" (%s)", creds.Tokens.AccountID)
		}
		fmt.Println()
	}
}

func cmdUsage() {
	cfg, err := loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "ourcodex: not logged in. Run: ourcodex login <server_url>")
		} else {
			fmt.Fprintf(os.Stderr, "ourcodex: config error: %v\n", err)
		}
		os.Exit(1)
	}

	// Call /api/user/usage on the proxy server
	req, err := http.NewRequest(http.MethodGet, cfg.ServerURL+"/api/user/usage", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ourcodex: failed to build request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ourcodex: request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "ourcodex: server returned %d\n", resp.StatusCode)
		os.Exit(1)
	}

	var data struct {
		TotalRequests int64 `json:"total_requests"`
		TotalInput    int64 `json:"total_input"`
		TotalOutput   int64 `json:"total_output"`
		Last7Days     []struct {
			Day          string `json:"day"`
			TotalReqs    int64  `json:"total_requests"`
			InputTokens  int64  `json:"input_tokens"`
			OutputTokens int64  `json:"output_tokens"`
		} `json:"last_7_days"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		fmt.Fprintf(os.Stderr, "ourcodex: failed to parse response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Usage summary\n")
	fmt.Printf("─────────────────────────────────────\n")
	fmt.Printf("Total requests:  %d\n", data.TotalRequests)
	fmt.Printf("Input tokens:    %s\n", formatTokens(data.TotalInput))
	fmt.Printf("Output tokens:   %s\n", formatTokens(data.TotalOutput))
	fmt.Printf("\nLast 7 days:\n")
	fmt.Printf("  %-12s  %6s  %10s  %10s\n", "Date", "Reqs", "Input", "Output")
	fmt.Printf("  %-12s  %6s  %10s  %10s\n", "────", "────", "─────", "──────")
	for _, d := range data.Last7Days {
		fmt.Printf("  %-12s  %6d  %10s  %10s\n",
			d.Day, d.TotalReqs,
			formatTokens(d.InputTokens),
			formatTokens(d.OutputTokens),
		)
	}
}

func formatTokens(n int64) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

// syncOwnedAccount silently fetches the current credentials from the proxy
// isProxyReachable checks if the proxy server responds within 3 seconds.
func cmdMCPSync() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ourcodex: not logged in. Run: ourcodex login <server_url>")
		os.Exit(1)
	}

	req, err := http.NewRequest("GET", cfg.ServerURL+"/api/user/mcp-servers", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "server returned %d\n", resp.StatusCode)
		os.Exit(1)
	}

	var servers []struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Command string `json:"command"`
		Args    string `json:"args"`
		URL     string `json:"url"`
		Env     string `json:"env"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing response: %v\n", err)
		os.Exit(1)
	}

	if len(servers) == 0 {
		fmt.Println("No MCP servers configured on the proxy.")
		return
	}

	codexBin, err := exec.LookPath("codex")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ourcodex: 'codex' not found in PATH")
		os.Exit(1)
	}

	for _, s := range servers {
		// Replace existing definitions so repeated syncs are idempotent.
		_ = exec.Command(codexBin, "mcp", "remove", s.Name).Run()

		var commandArgs []string
		if s.Type == "http" || s.URL != "" {
			commandArgs = []string{"mcp", "add", s.Name, "--url", s.URL}
		} else {
			commandArgs = []string{"mcp", "add", s.Name}
			var environment map[string]string
			if s.Env != "" {
				_ = json.Unmarshal([]byte(s.Env), &environment)
			}
			for key, value := range environment {
				commandArgs = append(commandArgs, "--env", key+"="+value)
			}
			commandArgs = append(commandArgs, "--", s.Command)
			if s.Args != "" {
				var args []string
				_ = json.Unmarshal([]byte(s.Args), &args)
				commandArgs = append(commandArgs, args...)
			}
		}

		cmd := exec.Command(codexBin, commandArgs...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "error syncing MCP server %q: %v\n", s.Name, err)
			os.Exit(1)
		}
	}

	fmt.Printf("Synced %d MCP server(s) to ~/.codex/config.toml\n", len(servers))
}

func sudoUserHome() string {
	u := os.Getenv("SUDO_USER")
	if u == "" {
		return ""
	}
	// Common Linux/macOS pattern
	if _, err := os.Stat("/home/" + u); err == nil {
		return "/home/" + u
	}
	if _, err := os.Stat("/Users/" + u); err == nil {
		return "/Users/" + u
	}
	return ""
}

func isProxyReachable(cfg *Config) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(cfg.ServerURL + "/healthz")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// and updates ~/.codex/auth.json if they differ. This keeps the
// owner's local Codex CLI in sync after proxy token rotations.
func syncOwnedAccount(cfg *Config) {
	req, err := http.NewRequest(http.MethodGet, cfg.ServerURL+"/api/user/owned-account", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return // no owned account or server error — silent
	}

	var remote codexCredentials
	if err := json.NewDecoder(resp.Body).Decode(&remote); err != nil {
		return
	}
	if remote.Tokens.AccessToken == "" {
		return
	}

	// Compare with local credentials
	local := readLocalCreds()
	if local != nil &&
		local.Tokens.AccessToken == remote.Tokens.AccessToken &&
		local.Tokens.RefreshToken == remote.Tokens.RefreshToken {
		return // already in sync
	}

	// Merge: update token fields only, preserve scopes/subscriptionType/etc.
	mergeLocalCreds(&remote)
}

func runCodex(args []string) {
	cfg, err := loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "ourcodex: not logged in. Run: ourcodex login <server_url>")
		} else {
			fmt.Fprintf(os.Stderr, "ourcodex: config error: %v\n", err)
		}
		os.Exit(1)
	}

	// Check proxy reachability
	proxyOnline := isProxyReachable(cfg)

	if !proxyOnline {
		fmt.Fprintln(os.Stderr, "\033[33m⚠ Proxy unreachable — falling back to local credentials\033[0m")
	}

	// Show dashboard when launched with no arguments
	if args == nil {
		if proxyOnline {
			printDashboard(cfg)
		} else {
			fmt.Println("  Proxy offline. Using local Codex credentials.")
			fmt.Println()
		}
	}

	codexBin, err := exec.LookPath("codex")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ourcodex: 'codex' not found in PATH. Install Codex CLI first.")
		os.Exit(1)
	}

	// Save terminal state before launching Codex. If Codex exits without
	// restoring it (e.g. Ctrl+D in raw/TUI mode), we restore it ourselves.
	var savedTermState *term.State
	if term.IsTerminal(int(os.Stdin.Fd())) {
		savedTermState, _ = term.GetState(int(os.Stdin.Fd()))
	}

	codexArgs := args
	if proxyOnline {
		codexArgs = codexProviderArgs(cfg, args)
	}

	cmd := exec.Command(codexBin, codexArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if proxyOnline {
		cmd.Env = buildEnv(cfg)
	} else {
		// Offline: don't set proxy env vars, let Codex use local credentials
		cmd.Env = os.Environ()
	}

	// Forward signals to the child so Ctrl+C / SIGTERM reach Codex directly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				cmd.Process.Signal(sig) //nolint:errcheck
			}
		}
	}()

	runErr := cmd.Run()

	signal.Stop(sigCh)
	close(sigCh)

	// Restore terminal to the state it was in before Codex ran.
	// This fixes the "broken terminal" symptom after Ctrl+D in Codex's TUI.
	if savedTermState != nil {
		term.Restore(int(os.Stdin.Fd()), savedTermState) //nolint:errcheck
	}

	// Reset extended terminal modes that Codex's TUI may have left active:
	//   \x1b[?1l    — disable application cursor keys (DECCKM) → arrow keys back to \e[A
	//   \x1b[?2004l — disable bracketed paste mode
	//   \x1b[>4;0m  — disable modifyOtherKeys
	//   \x1b[<u     — pop kitty keyboard protocol stack (CSI-u mode → Ctrl+L = 8;133u)
	//   \x1b[?25h   — ensure cursor is visible
	if term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprint(os.Stdout, "\x1b[?1l\x1b[?2004l\x1b[>4;0m\x1b[<u\x1b[?25h")
	}

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

func codexProviderArgs(cfg *Config, args []string) []string {
	provider := fmt.Sprintf(
		`model_providers.ourcodex={ name = "OurCodex", base_url = %s, env_key = "OURCODEX_API_KEY", wire_api = "responses", requires_openai_auth = false, supports_websockets = false }`,
		strconv.Quote(strings.TrimRight(cfg.ServerURL, "/")+"/proxy/v1"),
	)
	return append([]string{"-c", `model_provider="ourcodex"`, "-c", provider}, args...)
}

func buildEnv(cfg *Config) []string {
	host := proxyHost(cfg.ServerURL)

	env := os.Environ()

	overrides := map[string]string{
		"OURCODEX_API_KEY": cfg.Token,
	}
	if host != "" {
		overrides["NO_PROXY"] = host
	}

	filtered := make([]string, 0, len(env))
	for _, e := range env {
		key := strings.SplitN(e, "=", 2)[0]
		if _, ok := overrides[key]; !ok {
			filtered = append(filtered, e)
		}
	}

	for k, v := range overrides {
		if v != "" {
			filtered = append(filtered, k+"="+v)
		}
		// empty value means "unset this var" — already removed from filtered above
	}

	return filtered
}

func cmdUpdate() {
	// Check write permissions before downloading
	selfPath, err := os.Executable()
	if err == nil {
		selfPath, _ = filepath.EvalSymlinks(selfPath)
		if f, err := os.OpenFile(selfPath+".test", os.O_CREATE|os.O_WRONLY, 0755); err != nil {
			fmt.Fprintln(os.Stderr, "Insufficient permissions. Run: sudo ourcodex update")
			os.Exit(1)
		} else {
			f.Close()
			os.Remove(selfPath + ".test")
		}
	}

	// Load config — try real user's home if running as sudo
	cfg, err := loadConfig()
	if err != nil && os.Getenv("SUDO_USER") != "" {
		// Running as sudo: try loading from the real user's home
		if sudoHome := sudoUserHome(); sudoHome != "" {
			altPath := filepath.Join(sudoHome, configFile)
			if data, e := os.ReadFile(altPath); e == nil {
				var c Config
				if json.Unmarshal(data, &c) == nil {
					cfg = &c
					err = nil
				}
			}
		}
	}
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "ourcodex: not logged in. Run: ourcodex login <server_url>")
		} else {
			fmt.Fprintf(os.Stderr, "ourcodex: config error: %v\n", err)
		}
		os.Exit(1)
	}

	platform := runtime.GOOS + "-" + runtime.GOARCH
	updateURL := cfg.ServerURL + "/api/user/update?platform=" + platform

	req, err := http.NewRequest(http.MethodGet, updateURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ourcodex: failed to build request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ourcodex: update request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "ourcodex: server returned %d\n", resp.StatusCode)
		os.Exit(1)
	}

	// Write to a temp file next to the current executable.
	selfPath, err = os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ourcodex: cannot find own path: %v\n", err)
		os.Exit(1)
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ourcodex: cannot resolve path: %v\n", err)
		os.Exit(1)
	}

	tmpPath := selfPath + ".new"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ourcodex: cannot write update: %v\n", err)
		os.Exit(1)
	}

	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "ourcodex: download failed: %v\n", err)
		os.Exit(1)
	}
	f.Close()

	if err := os.Rename(tmpPath, selfPath); err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "ourcodex: failed to replace binary: %v\n", err)
		os.Exit(1)
	}

	// Extract the embedded key from the sentinel (first 8 chars shown).
	key := strings.TrimPrefix(binaryToken, "OCBINTOK:")
	if len(key) > 8 {
		key = key[:8] + "..."
	}
	fmt.Printf("Updated successfully (platform: %s, key: %s)\n", platform, key)
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiCyan   = "\x1b[36m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiGray   = "\x1b[90m"
)

type dashMe struct {
	Name  string `json:"name"`
	Quota struct {
		DailyUsed     int64   `json:"daily_used"`
		DailyLimit    int64   `json:"daily_limit"`
		MonthlyUsed   int64   `json:"monthly_used"`
		MonthlyLimit  int64   `json:"monthly_limit"`
		MonthlyBudget float64 `json:"monthly_budget"`
	} `json:"quota"`
}

type dashPoolStatus struct {
	Pools []struct {
		ID       uint   `json:"id"`
		Name     string `json:"name"`
		Accounts struct {
			Active    int64 `json:"active"`
			Exhausted int64 `json:"exhausted"`
			Error     int64 `json:"error"`
		} `json:"accounts"`
	} `json:"pools"`
	Today struct {
		Requests     int64 `json:"requests"`
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
	} `json:"today"`
	Week struct {
		Requests     int64 `json:"requests"`
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
	} `json:"week"`
	OwnedAccount *struct {
		Status    string    `json:"status"`
		ExpiresAt time.Time `json:"expires_at"`
		LastError string    `json:"last_error"`
		Today     struct {
			Requests     int64 `json:"requests"`
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"today"`
		Week struct {
			Requests     int64 `json:"requests"`
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"week"`
	} `json:"owned_account"`
}

// ansiVisibleLen returns the visible length of s, ignoring ANSI escape sequences.
func ansiVisibleLen(s string) int {
	n := 0
	i := 0
	for i < len(s) {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && s[i] != 'm' {
				i++
			}
			if i < len(s) {
				i++
			}
		} else {
			_, size := utf8.DecodeRuneInString(s[i:])
			n++
			i += size
		}
	}
	return n
}

const dashBoxW = 64

func dashHR(l, r rune) string {
	return string(l) + strings.Repeat("─", dashBoxW-2) + string(r)
}

func dashRow(content string) string {
	vis := ansiVisibleLen(content)
	pad := (dashBoxW - 2) - vis
	if pad < 0 {
		pad = 0
	}
	return "│" + content + strings.Repeat(" ", pad) + "│"
}

func dashTwoCol(left, right string) string {
	half := (dashBoxW - 2) / 2
	lPad := half - ansiVisibleLen(left)
	if lPad < 0 {
		lPad = 0
	}
	rPad := (dashBoxW - 2) - half - ansiVisibleLen(right)
	if rPad < 0 {
		rPad = 0
	}
	return "│" + left + strings.Repeat(" ", lPad) + right + strings.Repeat(" ", rPad) + "│"
}

func dashProgressBar(used, limit int64, width int) string {
	if limit <= 0 {
		return ansiGray + strings.Repeat("░", width) + ansiReset
	}
	p := float64(used) / float64(limit)
	if p > 1 {
		p = 1
	}
	filled := int(p * float64(width))
	color := ansiGreen
	if p >= 0.9 {
		color = ansiRed
	} else if p >= 0.7 {
		color = ansiYellow
	}
	return color + strings.Repeat("█", filled) + ansiGray + strings.Repeat("░", width-filled) + ansiReset
}

func dashPct(used, limit int64) string {
	if limit <= 0 {
		return " — "
	}
	return fmt.Sprintf("%3.0f%%", float64(used)*100/float64(limit))
}

func fetchDashboardData(cfg *Config) (dashMe, dashPoolStatus) {
	var me dashMe
	var ps dashPoolStatus
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 5 * time.Second}

	fetchJSON := func(path string, dst interface{}) {
		defer wg.Done()
		req, err := http.NewRequest(http.MethodGet, cfg.ServerURL+path, nil)
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			json.NewDecoder(resp.Body).Decode(dst) //nolint:errcheck
		}
	}

	wg.Add(2)
	go fetchJSON("/api/user/me", &me)
	go fetchJSON("/api/user/pool-status", &ps)
	wg.Wait()
	return me, ps
}

func printDashboard(cfg *Config) {
	me, ps := fetchDashboardData(cfg)

	// Header
	fmt.Println(dashHR('┌', '┐'))
	header := " " + ansiBold + ansiCyan + "✦ OurCodex" + ansiReset
	if me.Name != "" {
		header += "  ─  " + ansiBold + me.Name + ansiReset
	}
	fmt.Println(dashRow(header))
	fmt.Println(dashHR('├', '┤'))

	// Today vs This Week
	fmt.Println(dashTwoCol(
		" "+ansiBold+"TODAY"+ansiReset+"                         ",
		" "+ansiBold+"THIS WEEK"+ansiReset+"                     ",
	))
	fmt.Println(dashTwoCol(
		fmt.Sprintf(" %s reqs", formatTokens(ps.Today.Requests)),
		fmt.Sprintf(" %s reqs", formatTokens(ps.Week.Requests)),
	))
	fmt.Println(dashTwoCol(
		fmt.Sprintf(" In %-7s  Out %s", formatTokens(ps.Today.InputTokens), formatTokens(ps.Today.OutputTokens)),
		fmt.Sprintf(" In %-7s  Out %s", formatTokens(ps.Week.InputTokens), formatTokens(ps.Week.OutputTokens)),
	))
	fmt.Println(dashHR('├', '┤'))

	// Pool status
	for _, p := range ps.Pools {
		fmt.Println(dashRow(fmt.Sprintf(" Pool: %s%s%s", ansiBold, p.Name, ansiReset)))
		accts := fmt.Sprintf("   %s● %d active%s   %s◐ %d exhausted%s   %s✗ %d error%s",
			ansiGreen, p.Accounts.Active, ansiReset,
			ansiYellow, p.Accounts.Exhausted, ansiReset,
			ansiRed, p.Accounts.Error, ansiReset,
		)
		fmt.Println(dashRow(accts))
	}
	if len(ps.Pools) == 0 {
		fmt.Println(dashRow(" " + ansiGray + "No pool assigned" + ansiReset))
	}
	fmt.Println(dashHR('├', '┤'))

	// Quota
	barW := 20
	hasQuota := false
	if me.Quota.DailyLimit > 0 {
		hasQuota = true
		bar := dashProgressBar(me.Quota.DailyUsed, me.Quota.DailyLimit, barW)
		fmt.Println(dashRow(fmt.Sprintf(" Daily   %s  %s  %s / %s",
			bar,
			dashPct(me.Quota.DailyUsed, me.Quota.DailyLimit),
			formatTokens(me.Quota.DailyUsed),
			formatTokens(me.Quota.DailyLimit),
		)))
	}
	if me.Quota.MonthlyLimit > 0 {
		hasQuota = true
		bar := dashProgressBar(me.Quota.MonthlyUsed, me.Quota.MonthlyLimit, barW)
		fmt.Println(dashRow(fmt.Sprintf(" Monthly %s  %s  %s / %s",
			bar,
			dashPct(me.Quota.MonthlyUsed, me.Quota.MonthlyLimit),
			formatTokens(me.Quota.MonthlyUsed),
			formatTokens(me.Quota.MonthlyLimit),
		)))
	}
	if !hasQuota {
		fmt.Println(dashRow(" " + ansiGray + "No quota configured" + ansiReset))
	}

	// Personal account (if user owns one)
	if ps.OwnedAccount != nil {
		fmt.Println(dashHR('├', '┤'))
		acc := ps.OwnedAccount
		statusColor := ansiGreen
		statusIcon := "●"
		if acc.Status == "exhausted" {
			statusColor = ansiYellow
			statusIcon = "◐"
		} else if acc.Status == "error" {
			statusColor = ansiRed
			statusIcon = "✗"
		}
		expStr := ""
		if !acc.ExpiresAt.IsZero() {
			if time.Now().After(acc.ExpiresAt) {
				expStr = "  " + ansiRed + "token expired" + ansiReset
			} else {
				expStr = "  expires " + acc.ExpiresAt.Format("2006-01-02 15:04")
			}
		}
		fmt.Println(dashRow(fmt.Sprintf(" ◎ Personal account  %s%s %s%s%s",
			statusColor, statusIcon, acc.Status, ansiReset, expStr,
		)))
		fmt.Println(dashTwoCol(
			fmt.Sprintf("   today   %s reqs", formatTokens(acc.Today.Requests)),
			fmt.Sprintf("   week    %s reqs", formatTokens(acc.Week.Requests)),
		))
		fmt.Println(dashTwoCol(
			fmt.Sprintf("   In %-7s  Out %s", formatTokens(acc.Today.InputTokens), formatTokens(acc.Today.OutputTokens)),
			fmt.Sprintf("   In %-7s  Out %s", formatTokens(acc.Week.InputTokens), formatTokens(acc.Week.OutputTokens)),
		))
	}

	fmt.Println(dashHR('└', '┘'))
	fmt.Println()
}

func printHelp() {
	fmt.Print(`ourcodex - Codex CLI wrapper using OurCodex proxy

Usage:
  ourcodex init <server_url> [token]    Setup proxy + optionally share your Codex account
  ourcodex login <server_url> [token]   Configure proxy connection (no account sharing)
  ourcodex logout                       Remove proxy configuration
  ourcodex status                       Show current configuration
  ourcodex usage                        Show your token usage stats
  ourcodex update                       Download and replace with latest binary
  ourcodex uninstall                    Remove ourcodex binary and config
  ourcodex mcp-sync                     Sync MCP servers from proxy to local settings
  ourcodex [codex-args...]             Run codex through the proxy

Examples:
  ourcodex init http://proxy.example.com:8080
  ourcodex init http://proxy.example.com:8080 sk-proxy-abc123
  ourcodex login http://proxy.example.com:8080
  ourcodex "explain this code"
  ourcodex "write tests for this"
  ourcodex usage
  ourcodex status
  ourcodex logout

Config stored in: ~/.ourcodex/config.json

Account sharing (ourcodex init):
  If you have a Codex account connected locally, ourcodex init will offer to share
  it with the proxy. The proxy will automatically keep your local credentials
  (~/.codex/auth.json) in sync after token rotations.
`)
}
