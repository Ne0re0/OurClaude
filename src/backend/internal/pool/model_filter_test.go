package pool

import (
	"testing"

	"claude-proxy/internal/database"
)

func TestFilterForModel(t *testing.T) {
	accounts := []database.ClaudeAccount{
		{ID: 1},
		{ID: 2, MythosModels: "claude-mythos-5-1"},
		{ID: 3, MythosModels: "claude-mythos-5-2"},
		{ID: 4, MythosModels: "claude-mythos-5-1,claude-mythos-5-2"},
	}
	for _, tc := range []struct {
		model string
		want  []uint
	}{
		{"claude-opus-5-5", []uint{1, 2, 3, 4}},
		{"claude-mythos-5-1", []uint{2, 4}},
		{"claude-mythos-5-2", []uint{3, 4}},
		{"claude-mythos-5-2[1m]", []uint{3, 4}},
	} {
		got := filterForModel(accounts, tc.model)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %d accounts, want %d", tc.model, len(got), len(tc.want))
		}
		for i, account := range got {
			if account.ID != tc.want[i] {
				t.Fatalf("%s: account %d = %d, want %d", tc.model, i, account.ID, tc.want[i])
			}
		}
	}
}

func TestMythosSelectionUsesAssignedAccount(t *testing.T) {
	manager, poolID, accounts := newSelectionTestManager(t, 10, 20)
	if err := manager.db.Model(&database.ClaudeAccount{}).Where("id = ?", accounts[1].ID).
		Update("mythos_models", "claude-mythos-5-2").Error; err != nil {
		t.Fatal(err)
	}
	selected, err := manager.GetAccountForUserExcludingModel([]uint{poolID}, nil, "claude-mythos-5-2")
	if err != nil {
		t.Fatal(err)
	}
	if selected.ID != accounts[1].ID {
		t.Fatalf("selected %d, want %d", selected.ID, accounts[1].ID)
	}
	if _, err := manager.GetAccountForUserExcludingModel([]uint{poolID}, nil, "claude-mythos-5-1"); err == nil {
		t.Fatal("expected no eligible account for unassigned Mythos model")
	}
}
