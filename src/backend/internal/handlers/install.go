package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"codex-proxy/internal/database"

	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
)

type InstallHandler struct {
	db *gorm.DB
}

func NewInstallHandler(db *gorm.DB) *InstallHandler {
	return &InstallHandler{db: db}
}

// GET /api/install/{token} — returns a bash install script with embedded credentials
func (h *InstallHandler) Script(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")

	// Try setup token first
	var setup database.SetupToken
	if err := h.db.Where("token = ? AND expires_at > ?", token, time.Now()).First(&setup).Error; err != nil {
		http.Error(w, "invalid or expired token", http.StatusNotFound)
		return
	}

	var user database.User
	if err := h.db.First(&user, setup.UserID).Error; err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	// Get server URL from request
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
		scheme = fwd
	}
	serverURL := fmt.Sprintf("%s://%s", scheme, r.Host)

	// Generate download links for all platforms
	dlLinks := CreateLinksForUser(h.db, user.ID, 3)
	autoShare := r.URL.Query().Get("no-share") != "1"

	script := generateInstallScript(serverURL, user.APIToken, dlLinks, autoShare)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

func generateInstallScript(serverURL, apiToken string, dlLinks map[string]string, autoShare bool) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("set -euo pipefail\n\n")
	sb.WriteString("# OurCodex automatic installer\n")
	sb.WriteString(fmt.Sprintf("SERVER=%q\n", serverURL))
	sb.WriteString(fmt.Sprintf("TOKEN=%q\n\n", apiToken))

	sb.WriteString("OS=$(uname -s | tr '[:upper:]' '[:lower:]')\n")
	sb.WriteString("ARCH=$(uname -m)\n")
	sb.WriteString("case \"$ARCH\" in\n")
	sb.WriteString("    x86_64)        ARCH=\"amd64\" ;;\n")
	sb.WriteString("    aarch64|arm64) ARCH=\"arm64\" ;;\n")
	sb.WriteString("esac\n")
	sb.WriteString("PLATFORM=\"${OS}-${ARCH}\"\n\n")

	sb.WriteString("echo \"Installing ourcodex for ${PLATFORM}...\"\n\n")

	sb.WriteString("case \"$PLATFORM\" in\n")
	for platform, dlPath := range dlLinks {
		sb.WriteString(fmt.Sprintf("    %s)\n", platform))
		sb.WriteString(fmt.Sprintf("        curl -fsSL \"%s%s\" -o /usr/local/bin/ourcodex\n", serverURL, dlPath))
		sb.WriteString("        ;;\n")
	}
	sb.WriteString("    *)\n")
	sb.WriteString("        echo \"Unsupported platform: ${PLATFORM}\"\n")
	sb.WriteString("        exit 1\n")
	sb.WriteString("        ;;\n")
	sb.WriteString("esac\n\n")

	sb.WriteString("chmod +x /usr/local/bin/ourcodex\n")
	sb.WriteString("echo \"Binary installed to /usr/local/bin/ourcodex\"\n\n")

	shareFlag := ""
	if autoShare {
		shareFlag = " --setup-login"
	} else {
		shareFlag = " --no-share"
	}
	sb.WriteString("# Auto-login as the real user (not root)\n")
	sb.WriteString("if [ -n \"${SUDO_USER:-}\" ]; then\n")
	sb.WriteString("    echo \"Configuring for user: $SUDO_USER\"\n")
	sb.WriteString(fmt.Sprintf("    sudo -H -u \"$SUDO_USER\" ourcodex login \"$SERVER\" \"$TOKEN\"%s\n", shareFlag))
	sb.WriteString("else\n")
	sb.WriteString(fmt.Sprintf("    ourcodex login \"$SERVER\" \"$TOKEN\"%s\n", shareFlag))
	sb.WriteString("fi\n")
	sb.WriteString("echo \"\"\n")
	sb.WriteString("echo \"Done! Run 'ourcodex' to start using Codex.\"\n")

	return sb.String()
}
