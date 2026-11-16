package proxy

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// Recorded shape of the ChatGPT plan route: SSE framing served as text/plain.
const (
	completedStream = "event: response.created\n" +
		`data: {"type":"response.created","sequence_number":0,"response":{"id":"resp_1","status":"in_progress","model":"gpt-6-luna"}}` + "\n\n" +
		"event: response.in_progress\n" +
		`data: {"type":"response.in_progress","sequence_number":1,"response":{"id":"resp_1","status":"in_progress","model":"gpt-6-luna"}}` + "\n\n" +
		"event: response.metadata\n" +
		`data: {"type":"response.metadata","sequence_number":2,"metadata":{}}` + "\n\n" +
		"event: response.output_text.delta\n" +
		`data: {"type":"response.output_text.delta","sequence_number":3,"delta":"OK"}` + "\n\n" +
		"event: response.completed\n" +
		`data: {"type":"response.completed","sequence_number":4,"response":{"id":"resp_1","status":"completed","model":"gpt-6-luna",` +
		`"usage":{"input_tokens":23,"input_tokens_details":{"cached_tokens":4,"cache_write_tokens":0},"output_tokens":5,"total_tokens":28}}}` + "\n\n"

	limitedStream = "event: response.created\n" +
		`data: {"type":"response.created","sequence_number":0,"response":{"id":"resp_2","status":"in_progress","model":"gpt-6-luna"}}` + "\n\n" +
		"event: response.metadata\n" +
		`data: {"type":"response.metadata","sequence_number":1,"metadata":{}}` + "\n\n" +
		"event: response.failed\n" +
		`data: {"type":"response.failed","sequence_number":2,"response":{"id":"resp_2","status":"failed","model":"gpt-6-luna",` +
		`"error":{"code":"subscription_sharing_usage_limit_exceeded","message":"usage limit reached"}}}` + "\n\n"

	lateLimitStream = "event: response.created\n" +
		`data: {"type":"response.created","sequence_number":0,"response":{"id":"resp_3","status":"in_progress","model":"gpt-6-luna"}}` + "\n\n" +
		"event: response.output_text.delta\n" +
		`data: {"type":"response.output_text.delta","sequence_number":1,"delta":"partial"}` + "\n\n" +
		"event: response.failed\n" +
		`data: {"type":"response.failed","sequence_number":2,"response":{"id":"resp_3","status":"failed","model":"gpt-6-luna",` +
		`"error":{"code":"subscription_sharing_usage_limit_exceeded","message":"usage limit reached"}}}` + "\n\n"
)

func TestLooksLikeSSE(t *testing.T) {
	for body, want := range map[string]bool{
		completedStream:          true,
		"\xef\xbb\xbfevent: x\n": true,
		"\r\n data:{}\n\n":       true,
		": keep-alive\n\n":       true,
		`{"id":"resp_1"}`:        false,
		"":                       false,
	} {
		if got := looksLikeSSE([]byte(body)); got != want {
			t.Errorf("looksLikeSSE(%q) = %v, want %v", body, got, want)
		}
	}
}

func TestCannotBeSSE(t *testing.T) {
	for body, want := range map[string]bool{
		"":          false,
		"\n":        false,
		"e":         false, // may still become "event:"
		"da":        false,
		"data: {}":  false,
		"{":         true,
		"<html>":    true,
		"evil":      true,
		"\xef\xbb":  true, // a truncated BOM is not stripped; rare enough to skip the check
		"\r\n even": false,
	} {
		if got := cannotBeSSE([]byte(body)); got != want {
			t.Errorf("cannotBeSSE(%q) = %v, want %v", body, got, want)
		}
	}
}

func TestSSEData(t *testing.T) {
	body := "event: a\r\ndata: {\"n\":1}\r\n\r\ndata:{\"n\":2}\n\ndata: line1\ndata: line2\n\ndata: partial"
	var got []string
	for _, payload := range sseData([]byte(body), false) {
		got = append(got, string(payload))
	}
	want := []string{`{"n":1}`, `{"n":2}`, "line1\nline2"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("sseData = %q, want %q", got, want)
	}
	if final := sseData([]byte(body), true); string(final[len(final)-1]) != "partial" {
		t.Fatalf("final event not included: %q", final)
	}
}

func TestPeekLeadingFailure(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"usage limit before output", limitedStream, codeUsageLimitExceeded},
		{"completed stream", completedStream, ""},
		{"limit after output", lateLimitStream, ""},
		{"other failure", strings.Replace(limitedStream, codeUsageLimitExceeded, "server_error", 1), ""},
		{"usage unavailable", strings.Replace(limitedStream, codeUsageLimitExceeded, codeUsageUnavailable, 1), codeUsageUnavailable},
		{"json response", `{"id":"resp_1","status":"completed"}`, ""},
	}
	for _, tc := range cases {
		// One byte per read exercises events split across reads.
		reader := io.NopCloser(iotest.OneByteReader(strings.NewReader(tc.body)))
		prefix, failure := peekLeadingFailure(reader)
		if failure != tc.want {
			t.Errorf("%s: failure = %q, want %q", tc.name, failure, tc.want)
		}
		replayed, err := io.ReadAll(newReplayBody(prefix, reader))
		if err != nil || !bytes.Equal(replayed, []byte(tc.body)) {
			t.Errorf("%s: replayed body differs (err %v)", tc.name, err)
		}
	}
}

func TestEstimateCostCoversCodexModels(t *testing.T) {
	// Budgets are enforced from these estimates, so a missing model would
	// make its usage free and its budget unenforceable.
	for model, want := range map[string]float64{
		"gpt-6.1-sol":   2.0 + 10.0,
		"gpt-6-sol":     2.0 + 10.0,
		"gpt-6-astra":   10.0 + 50.0,
		"gpt-6.1-terra": 1.0 + 5.0,
		"gpt-6-luna":    0.10 + 0.50,
		"gpt-5.6-terra": 2.0 + 12.0,
		"gpt-5.6-luna":  0.20 + 1.20,
	} {
		if got := estimateCostRow(model, 1_000_000, 1_000_000); got < want-1e-9 || got > want+1e-9 {
			t.Errorf("estimateCostRow(%q) = %v, want %v", model, got, want)
		}
	}
}
