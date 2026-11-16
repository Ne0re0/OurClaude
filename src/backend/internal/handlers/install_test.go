package handlers

import (
	"strings"
	"testing"
)

func TestSetupInstallerStartsDedicatedCodexLogin(t *testing.T) {
	withLogin := generateInstallScript("https://proxy.example", "sk-proxy-example", map[string]string{
		"linux-amd64": "/download/test",
	}, true)
	if !strings.Contains(withLogin, `sudo -H -u "$SUDO_USER" ourcodex login "$SERVER" "$TOKEN" --setup-login`) {
		t.Fatal("setup installer does not start dedicated Codex login as the user")
	}
	withoutLogin := generateInstallScript("https://proxy.example", "sk-proxy-example", nil, false)
	if strings.Contains(withoutLogin, "--setup-login") || !strings.Contains(withoutLogin, "--no-share") {
		t.Fatal("no-share installer still starts Codex login or sharing")
	}
}
