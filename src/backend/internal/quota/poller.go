package quota

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"codex-proxy/internal/database"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Poller is retained as a lightweight lifecycle component for the admin API.
// Codex rate limits are supplied on real Responses API traffic, so polling a
// separate undocumented endpoint would be both brittle and unnecessary.
type Poller struct{}

func New() *Poller { return &Poller{} }

func (p *Poller) Start(context.Context) {
	log.Println("quota: collecting x-codex rate-limit headers from proxy responses")
}

func (p *Poller) PollNow() {}

// UpdateFromHeaders stores the default Codex primary/secondary windows and
// credit snapshot returned by the ChatGPT Codex backend.
func UpdateFromHeaders(db *gorm.DB, accountID uint, headers http.Header) {
	primaryPct, hasPrimary := floatHeader(headers, "x-codex-primary-used-percent")
	secondaryPct, hasSecondary := floatHeader(headers, "x-codex-secondary-used-percent")
	creditsHas, hasCredits := boolHeader(headers, "x-codex-credits-has-credits")
	if !hasPrimary && !hasSecondary && !hasCredits {
		return
	}

	primaryWindow, _ := intHeader(headers, "x-codex-primary-window-minutes")
	secondaryWindow, _ := intHeader(headers, "x-codex-secondary-window-minutes")
	primaryReset, _ := intHeader(headers, "x-codex-primary-reset-at")
	secondaryReset, _ := intHeader(headers, "x-codex-secondary-reset-at")
	creditsUnlimited, _ := boolHeader(headers, "x-codex-credits-unlimited")

	raw := map[string]string{}
	for key, values := range headers {
		if strings.HasPrefix(strings.ToLower(key), "x-codex-") && len(values) > 0 {
			raw[strings.ToLower(key)] = values[0]
		}
	}
	rawJSON, _ := json.Marshal(raw)

	quota := database.AccountQuota{
		AccountID:        accountID,
		PrimaryPct:       primaryPct,
		PrimaryResets:    unixTimeString(primaryReset),
		SecondaryPct:     secondaryPct,
		SecondaryResets:  unixTimeString(secondaryReset),
		CreditsHas:       creditsHas,
		CreditsUnlimited: creditsUnlimited,
		CreditsBalance:   headers.Get("x-codex-credits-balance"),
		RawJSON:          string(rawJSON),
		Error:            "",
		UpdatedAt:        time.Now(),
	}
	if primaryWindow > 0 {
		quota.PrimaryWindowMinutes = &primaryWindow
	}
	if secondaryWindow > 0 {
		quota.SecondaryWindowMinutes = &secondaryWindow
	}

	db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "account_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"primary_pct", "primary_window_minutes", "primary_resets",
			"secondary_pct", "secondary_window_minutes", "secondary_resets",
			"credits_has", "credits_unlimited", "credits_balance",
			"raw_json", "error", "updated_at",
		}),
	}).Create(&quota)

	if primaryPct < 100 {
		db.Model(&database.CodexAccount{}).
			Where("id = ? AND status = ?", accountID, "exhausted").
			Updates(map[string]interface{}{"status": "active", "last_error": ""})
	}
}

func floatHeader(headers http.Header, name string) (float64, bool) {
	value := strings.TrimSpace(headers.Get(name))
	if value == "" {
		return 0, false
	}
	n, err := strconv.ParseFloat(value, 64)
	return n, err == nil
}

func intHeader(headers http.Header, name string) (int64, bool) {
	value := strings.TrimSpace(headers.Get(name))
	if value == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return n, err == nil
}

func boolHeader(headers http.Header, name string) (bool, bool) {
	value := strings.TrimSpace(headers.Get(name))
	if value == "" {
		return false, false
	}
	n, err := strconv.ParseBool(value)
	return n, err == nil
}

func unixTimeString(seconds int64) string {
	if seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}
