package proxy

import (
	"math"
	"reflect"
	"testing"

	"claude-proxy/internal/database"
)

func TestAllowedUpstreamRoute(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		{"POST", "/v1/messages", true},
		{"POST", "/v1/messages/count_tokens", true},
		{"GET", "/v1/models", true},
		{"GET", "/v1/messages", false},
		{"POST", "/v1/messages/batches", false},
		{"GET", "/api/oauth/profile", false},
		{"DELETE", "/v1/files/file_123", false},
		{"POST", "/v1/messages/../../api/oauth/profile", false},
		{"POST", "/v1/messages/", false},
	}
	for _, c := range cases {
		if got := allowedUpstreamRoute(c.method, c.path); got != c.want {
			t.Errorf("allowedUpstreamRoute(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

func TestEstimateCostRow(t *testing.T) {
	cases := []struct {
		name                              string
		model                             string
		input, output, cacheRead, cacheWr int64
		want                              float64
	}{
		{"opus 5.5 is not priced as opus 5", "claude-opus-5-5", 1_000_000, 0, 0, 0, 4},
		{"cache reads use the model's rate", "claude-opus-5-5", 0, 0, 1_000_000, 0, 0.20},
		{"cache writes cost 1.25x input", "claude-sonnet-4-6", 0, 0, 0, 1_000_000, 3.75},
		{"output tokens", "claude-sonnet-5-5", 0, 1_000_000, 0, 0, 10},
		{"older opus 4 keeps its price", "claude-opus-4-1", 1_000_000, 0, 0, 0, 15},
		{"unknown model is charged the top rate", "claude-future-9", 1_000_000, 0, 0, 0, 10},
	}
	for _, c := range cases {
		got := estimateCostRow(c.model, c.input, c.output, c.cacheRead, c.cacheWr)
		if math.Abs(got-c.want) > 1e-9 {
			t.Errorf("%s: estimateCostRow = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPoolsWithinQuota(t *testing.T) {
	quotaPools := []database.Pool{
		{ID: 2, DailyTokenQuota: 100},
		{ID: 3, MonthlyTokenQuota: 1000},
	}
	daily := map[uint]int64{2: 100}
	monthly := map[uint]int64{3: 999}

	got := poolsWithinQuota([]uint{1, 2, 3}, quotaPools, daily, monthly)
	if want := []uint{1, 3}; !reflect.DeepEqual(got, want) {
		t.Errorf("poolsWithinQuota = %v, want %v (pool 2 hit its daily quota)", got, want)
	}

	monthly[3] = 1000
	if got := poolsWithinQuota([]uint{2, 3}, quotaPools, daily, monthly); len(got) != 0 {
		t.Errorf("poolsWithinQuota = %v, want none when every pool is exhausted", got)
	}
}
