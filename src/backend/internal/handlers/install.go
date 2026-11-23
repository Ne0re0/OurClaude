package handlers

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"claude-proxy/internal/database"
	"claude-proxy/internal/middleware"

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

	serverURL, ok := publicServerURL(r)
	if !ok {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	dlLinks := CreateLinksForUser(h.db, user.ID, 3)
	autoShare := r.URL.Query().Get("no-share") != "1"

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(generateInstallScript(serverURL, user.APIToken, dlLinks, autoShare)))
}

var hostPattern = regexp.MustCompile(`^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?$`)

// publicServerURL is the URL clients use to reach this server. The scheme comes
// from a trusted reverse proxy only and the host must be a plain hostname, since
// the result ends up in scripts run as root and in the CLI's update origin.
func publicServerURL(r *http.Request) (string, bool) {
	if !hostPattern.MatchString(r.Host) {
		return "", false
	}
	scheme := "http"
	if middleware.RequestIsHTTPS(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host, true
}

// shellQuote single-quotes s for bash, where nothing inside single quotes expands.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func generateInstallScript(serverURL, apiToken string, dlLinks map[string]string, autoShare bool) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("set -euo pipefail\n\n")
	sb.WriteString("# OurClaude automatic installer\n")
	sb.WriteString("SERVER=" + shellQuote(serverURL) + "\n")
	sb.WriteString("TOKEN=" + shellQuote(apiToken) + "\n\n")

	sb.WriteString("OS=$(uname -s | tr '[:upper:]' '[:lower:]')\n")
	sb.WriteString("ARCH=$(uname -m)\n")
	sb.WriteString("case \"$ARCH\" in\n")
	sb.WriteString("    x86_64)        ARCH=\"amd64\" ;;\n")
	sb.WriteString("    aarch64|arm64) ARCH=\"arm64\" ;;\n")
	sb.WriteString("esac\n")
	sb.WriteString("PLATFORM=\"${OS}-${ARCH}\"\n\n")

	sb.WriteString("echo \"Installing ourclaude for ${PLATFORM}...\"\n\n")

	platforms := make([]string, 0, len(dlLinks))
	for p := range dlLinks {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)
	sb.WriteString("case \"$PLATFORM\" in\n")
	for _, platform := range platforms {
		sb.WriteString(fmt.Sprintf("    %s)\n", shellQuote(platform)))
		sb.WriteString("        curl -fsSL \"${SERVER}\"" + shellQuote(dlLinks[platform]) + " -o /usr/local/bin/ourclaude\n")
		sb.WriteString("        ;;\n")
	}
	sb.WriteString("    *)\n")
	sb.WriteString("        echo \"Unsupported platform: ${PLATFORM}\"\n")
	sb.WriteString("        exit 1\n")
	sb.WriteString("        ;;\n")
	sb.WriteString("esac\n\n")

	sb.WriteString("chmod +x /usr/local/bin/ourclaude\n")
	sb.WriteString("echo \"Binary installed to /usr/local/bin/ourclaude\"\n\n")

	sb.WriteString(rtkInstallScript)

	shareFlag := ""
	if autoShare {
		shareFlag = " --auto-share"
	}
	sb.WriteString("# Auto-login as the real user (not root)\n")
	sb.WriteString("if [ -n \"${SUDO_USER:-}\" ]; then\n")
	sb.WriteString("    echo \"Configuring for user: $SUDO_USER\"\n")
	sb.WriteString(fmt.Sprintf("    sudo -u \"$SUDO_USER\" ourclaude login \"$SERVER\" \"$TOKEN\"%s\n", shareFlag))
	sb.WriteString("else\n")
	sb.WriteString(fmt.Sprintf("    ourclaude login \"$SERVER\" \"$TOKEN\"%s\n", shareFlag))
	sb.WriteString("fi\n")
	sb.WriteString("echo \"\"\n")
	sb.WriteString("echo \"Done! Run 'ourclaude' to start using Claude.\"\n")

	return sb.String()
}

// rtkInstallScript installs RTK (token optimizer) from a pinned release, checked
// against SHA-256 sums recorded here rather than ones fetched from the same
// release, so a tampered upstream cannot change what runs. No third-party script
// is executed; `rtk init` runs as the invoking user so it configures their Claude.
// To upgrade, bump the version and copy the sums from that release's checksums.txt
// after verifying the archives.
const rtkInstallScript = `# Install RTK token optimizer (pinned v1.2.1, checksum-verified)
install_rtk() {
    local target sum tmp actual
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64|Linux-amd64)  target="x86_64-unknown-linux-musl";  sum="75f64525711be935657a6b228d929c24bd9d1ab7d640ea374a8b913e5b5bac05" ;;
        Linux-aarch64|Linux-arm64) target="aarch64-unknown-linux-musl"; sum="cae1a911eda9e898dbb90039436e9d53922b20afb1e3e4ae341f749eb62b7781" ;;
        Darwin-x86_64)             target="x86_64-apple-darwin";        sum="107e272253c0aa36c9c85fbf9dd188bdb58d86c6ba9a85b49122420baf6e4c5c" ;;
        Darwin-arm64)              target="aarch64-apple-darwin";       sum="3bc2a92f1d3e404ef99c200cddcc0f4917d6c4ed5b127a751938a96f57d4ed9a" ;;
        *) echo "RTK: unsupported platform, skipping."; return 1 ;;
    esac
    tmp=$(mktemp -d)
    if ! curl -fsSL "https://github.com/rtk-ai/rtk/releases/download/v1.2.1/rtk-${target}.tar.gz" -o "$tmp/rtk.tar.gz"; then
        rm -rf "$tmp"; return 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$tmp/rtk.tar.gz" | cut -d' ' -f1)
    else
        actual=$(shasum -a 256 "$tmp/rtk.tar.gz" | cut -d' ' -f1)
    fi
    if [ "$actual" != "$sum" ]; then
        echo "RTK: checksum mismatch, not installing."
        rm -rf "$tmp"; return 1
    fi
    tar -xzf "$tmp/rtk.tar.gz" -C "$tmp" rtk && install -m 0755 "$tmp/rtk" /usr/local/bin/rtk
    local rc=$?
    rm -rf "$tmp"
    return $rc
}

echo "Installing RTK token optimizer..."
if command -v rtk >/dev/null 2>&1; then
    echo "RTK already installed, skipping."
elif install_rtk; then
    if [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" -H /usr/local/bin/rtk init --global 2>/dev/null || true
    else
        /usr/local/bin/rtk init --global 2>/dev/null || true
    fi
    echo "RTK installed and configured."
else
    echo "RTK installation failed (optional, continuing)."
fi

`
