package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

const codexUsageURL = "https://chatgpt.com/backend-api/wham/usage"

// ensureSetupCodexLogin gives setup links their own Codex login. The normal
// ~/.codex/auth.json is left alone, so its refresh-token rotations cannot
// invalidate the proxy's copy.
func ensureSetupCodexLogin() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("find home directory: %w", err)
	}
	cli, err := findCodexCLI(home)
	if err != nil {
		return err
	}
	profile := filepath.Join(home, setupCodexHome)
	if err := os.MkdirAll(profile, 0700); err != nil {
		return fmt.Errorf("create Codex login directory: %w", err)
	}
	path := filepath.Join(profile, "auth.json")
	if creds := readCodexCredsAt(path); creds != nil {
		status, err := codexQuotaStatus(creds)
		if err == nil && status == http.StatusOK {
			fmt.Println("Existing dedicated Codex login is valid.")
			return nil
		}
		if err == nil && status == http.StatusUnauthorized {
			fmt.Println("Dedicated Codex login has expired. Opening a fresh sign-in...")
			if err := runSetupCodex(cli, profile, "logout"); err != nil {
				return fmt.Errorf("clear expired Codex login: %w", err)
			}
		} else if err != nil {
			return fmt.Errorf("check existing Codex login: %w", err)
		} else {
			return fmt.Errorf("check existing Codex login: usage endpoint returned HTTP %d", status)
		}
	}
	fmt.Println("Opening the official Codex browser login for this proxy...")
	if err := runSetupCodex(cli, profile, "login"); err != nil {
		return fmt.Errorf("Codex browser login: %w", err)
	}
	creds := readCodexCredsAt(path)
	if creds == nil {
		return fmt.Errorf("Codex login did not create a valid %s", path)
	}
	status, err := codexQuotaStatus(creds)
	if err != nil {
		return fmt.Errorf("verify Codex quota access: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("new Codex login cannot read quotas (HTTP %d)", status)
	}
	return nil
}

func findCodexCLI(home string) (string, error) {
	if cli, err := exec.LookPath("codex"); err == nil {
		return cli, nil
	}
	candidates := []string{
		filepath.Join(home, ".local", "bin", "codex"),
		filepath.Join(home, ".npm-global", "bin", "codex"),
	}
	nvm, _ := filepath.Glob(filepath.Join(home, ".nvm", "versions", "node", "*", "bin", "codex"))
	sort.Sort(sort.Reverse(sort.StringSlice(nvm)))
	candidates = append(candidates, nvm...)
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("install the official Codex CLI first, then rerun the setup command")
}

func runSetupCodex(cli, profile, subcommand string) error {
	cmd := exec.Command(cli, subcommand)
	cmd.Env = append(os.Environ(), "CODEX_HOME="+profile, "PATH="+filepath.Dir(cli)+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func codexQuotaStatus(creds *codexCredentials) (int, error) {
	req, err := http.NewRequest(http.MethodGet, codexUsageURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+creds.Tokens.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "codex-cli")
	if creds.Tokens.AccountID != "" {
		req.Header.Set("ChatGPT-Account-ID", creds.Tokens.AccountID)
	}
	client := &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
