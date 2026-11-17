package pool

import (
	"path/filepath"
	"testing"
	"time"

	"claude-proxy/internal/database"
)

type resetEvents struct{ events []string }

func (r *resetEvents) Dispatch(event string, _ interface{}) { r.events = append(r.events, event) }

func TestScheduledResetReminderAndExecution(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "reset.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Truncate(time.Second)
	resetAt := start.Add(6 * time.Hour)
	p := database.Pool{Name: "scheduled", ScheduledResetAt: &resetAt}
	if err := db.Create(&p).Error; err != nil {
		t.Fatal(err)
	}
	a := database.ClaudeAccount{Name: "exhausted", Status: "exhausted", LastError: "quota"}
	if err := db.Create(&a).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&database.AccountPool{PoolID: p.ID, AccountID: a.ID}).Error; err != nil {
		t.Fatal(err)
	}
	events := &resetEvents{}
	m := &Manager{db: db, webhooks: events}

	m.processScheduledResets(start)
	if len(events.events) != 0 {
		t.Fatalf("early reminder: %v", events.events)
	}
	m.processScheduledResets(start.Add(time.Hour))
	m.processScheduledResets(start.Add(2 * time.Hour))
	if len(events.events) != 1 || events.events[0] != "pool.reset.reminder" {
		t.Fatalf("want one reminder: %v", events.events)
	}
	m.processScheduledResets(resetAt)
	if err := db.First(&a, a.ID).Error; err != nil {
		t.Fatal(err)
	}
	if a.Status != "active" || a.LastError != "" {
		t.Fatalf("account was not reset: %+v", a)
	}
	var saved database.Pool
	if err := db.First(&saved, p.ID).Error; err != nil {
		t.Fatal(err)
	}
	if saved.ScheduledResetAt != nil {
		t.Fatalf("schedule was not cleared: %v", saved.ScheduledResetAt)
	}
	m.processScheduledResets(resetAt.Add(time.Hour))
	if len(events.events) != 1 {
		t.Fatalf("reminder repeated: %v", events.events)
	}
}

func TestOverdueScheduledResetRunsWithoutLateReminder(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "reset.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	resetAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	p := database.Pool{Name: "overdue", ScheduledResetAt: &resetAt}
	if err := db.Create(&p).Error; err != nil {
		t.Fatal(err)
	}
	events := &resetEvents{}
	m := &Manager{db: db, webhooks: events}
	m.processScheduledResets(time.Now())
	var saved database.Pool
	if err := db.First(&saved, p.ID).Error; err != nil || saved.ScheduledResetAt != nil {
		t.Fatalf("overdue reset remains scheduled: %v, %v", saved.ScheduledResetAt, err)
	}
	if len(events.events) != 0 {
		t.Fatalf("late reminder sent: %v", events.events)
	}
}
