package quota

import (
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"codex-proxy/internal/database"
)

func TestUpdateFromHeaders(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "quota.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	reset := time.Now().Add(time.Hour).Unix()
	headers := http.Header{
		"X-Codex-Primary-Used-Percent":     []string{"37.5"},
		"X-Codex-Primary-Window-Minutes":   []string{"300"},
		"X-Codex-Primary-Reset-At":         []string{strconv.FormatInt(reset, 10)},
		"X-Codex-Secondary-Used-Percent":   []string{"12"},
		"X-Codex-Secondary-Window-Minutes": []string{"10080"},
		"X-Codex-Credits-Has-Credits":      []string{"true"},
		"X-Codex-Credits-Balance":          []string{"42.00"},
	}
	UpdateFromHeaders(db, 9, headers)

	var got database.AccountQuota
	if err := db.Where("account_id = ?", 9).First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.PrimaryPct != 37.5 || got.PrimaryWindowMinutes == nil || *got.PrimaryWindowMinutes != 300 {
		t.Fatalf("unexpected primary quota: %#v", got)
	}
	if got.SecondaryPct != 12 || !got.CreditsHas || got.CreditsBalance != "42.00" {
		t.Fatalf("unexpected quota: %#v", got)
	}
}
