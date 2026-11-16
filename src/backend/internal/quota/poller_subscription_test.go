package quota

import (
	"encoding/json"
	"testing"
)

func TestMissingFiveHourWindow(t *testing.T) {
	for _, tc := range []struct {
		body      string
		available bool
	}{
		{`{"five_hour":null,"seven_day":{"utilization":40}}`, false},
		{`{"five_hour":{"utilization":25},"seven_day":{"utilization":40}}`, true},
	} {
		var response apiResponse
		if err := json.Unmarshal([]byte(tc.body), &response); err != nil {
			t.Fatal(err)
		}
		if (response.FiveHour != nil) != tc.available {
			t.Fatalf("%s: five hour available = %v", tc.body, response.FiveHour != nil)
		}
	}
}
