package proxy

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"claude-proxy/internal/database"
)

func TestFilterModelListUsesAccountsInUsersPools(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "models.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []database.ClaudeAccount{
		{ID: 1, Name: "eligible", AccessToken: "x", RefreshToken: "x", RefreshTokenHash: "hash-1", Status: "active", MythosModels: "claude-mythos-5-2"},
		{ID: 2, Name: "other-pool", AccessToken: "x", RefreshToken: "x", RefreshTokenHash: "hash-2", Status: "active", MythosModels: "claude-mythos-5-1"},
		{ID: 3, Name: "legacy", AccessToken: "x", RefreshToken: "x", RefreshTokenHash: "hash-3", Status: "active"},
	} {
		if err := db.Create(&account).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Exec("UPDATE claude_accounts SET mythos_models = NULL WHERE id = 3").Error; err != nil {
		t.Fatal(err)
	}
	for _, link := range []database.AccountPool{{AccountID: 1, PoolID: 1}, {AccountID: 2, PoolID: 2}, {AccountID: 3, PoolID: 1}} {
		if err := db.Create(&link).Error; err != nil {
			t.Fatal(err)
		}
	}
	h := &Handler{db: db}
	input := `{"type":"list","data":[{"id":"claude-mythos-5-1"},{"id":"claude-mythos-5-2"},{"id":"claude-opus-5-5"}],"has_more":false}`
	output, err := h.filterModelList(strings.NewReader(input), []uint{1})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Data) != 2 || result.Data[0].ID != "claude-mythos-5-2" || result.Data[1].ID != "claude-opus-5-5" {
		t.Fatalf("unexpected model list: %s", output)
	}
}

func TestFilterModelListAddsAssignedMythosMissingUpstream(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "models.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	account := database.ClaudeAccount{Name: "assigned", AccessToken: "x", RefreshToken: "x", RefreshTokenHash: "assigned-hash", Status: "active", MythosModels: "claude-mythos-5-2"}
	if err := db.Create(&account).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&database.AccountPool{AccountID: account.ID, PoolID: 1}).Error; err != nil {
		t.Fatal(err)
	}
	h := &Handler{db: db}
	output, err := h.filterModelList(strings.NewReader(`{"type":"list","data":[{"id":"claude-opus-5-5"}],"has_more":false}`), []uint{1})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Data) != 2 || result.Data[1].ID != "claude-mythos-5-2" {
		t.Fatalf("unexpected model list: %s", output)
	}
}
