package proxy

import (
	"bytes"
	"encoding/json"
	"io"
)

// Responses error codes OpenAI uses when a Sign in with ChatGPT account cannot
// spend more of its ChatGPT plan. They can arrive as an HTTP error before the
// stream opens or as a response.failed event after it has started.
const (
	codeUsageLimitExceeded = "subscription_sharing_usage_limit_exceeded"
	codeUsageUnavailable   = "subscription_sharing_usage_unavailable"
)

// maxStreamPeek bounds how much of a stream is buffered while checking it for
// a leading usage-limit failure.
const maxStreamPeek = 256 * 1024

// looksLikeSSE reports whether body starts like a server-sent event stream.
// The ChatGPT plan route streams Responses events as text/plain, so the
// Content-Type header alone does not identify a stream.
func looksLikeSSE(body []byte) bool {
	body = trimStreamStart(body)
	for _, marker := range sseMarkers {
		if bytes.HasPrefix(body, marker) {
			return true
		}
	}
	return false
}

var sseMarkers = [][]byte{[]byte("event:"), []byte("data:"), []byte(":")}

func trimStreamStart(body []byte) []byte {
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	return bytes.TrimLeft(body, " \t\r\n")
}

// cannotBeSSE reports whether body, which may be only the first bytes of a
// response, can no longer turn out to be an event stream.
func cannotBeSSE(body []byte) bool {
	body = trimStreamStart(body)
	if len(body) == 0 {
		return false
	}
	for _, marker := range sseMarkers {
		if bytes.HasPrefix(body, marker) || bytes.HasPrefix(marker, body) {
			return false
		}
	}
	return true
}

// sseData returns the data payload of each complete event in body, joining
// multi-line data fields as the SSE format specifies. A trailing event without
// its terminating blank line is included only when final is true.
func sseData(body []byte, final bool) [][]byte {
	body = bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
	body = bytes.ReplaceAll(body, []byte("\r"), []byte("\n"))
	blocks := bytes.Split(body, []byte("\n\n"))
	if !final {
		blocks = blocks[:len(blocks)-1] // the last block may still be arriving
	}
	var payloads [][]byte
	for _, block := range blocks {
		var data [][]byte
		for _, line := range bytes.Split(block, []byte("\n")) {
			if value, ok := bytes.CutPrefix(line, []byte("data:")); ok {
				data = append(data, bytes.TrimPrefix(value, []byte(" ")))
			}
		}
		if len(data) > 0 {
			payloads = append(payloads, bytes.Join(data, []byte("\n")))
		}
	}
	return payloads
}

// streamEvent holds the fields of a Responses stream event that the proxy
// reads for usage accounting and limit handling.
type streamEvent struct {
	Type  string `json:"type"`
	Delta string `json:"delta"`
	Code  string `json:"code"`
	Error *struct {
		Code string `json:"code"`
	} `json:"error"`
	Response struct {
		Model string `json:"model"`
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
			InputDetails struct {
				CachedTokens     int `json:"cached_tokens"`
				CacheWriteTokens int `json:"cache_write_tokens"`
			} `json:"input_tokens_details"`
		} `json:"usage"`
	} `json:"response"`
}

// failureCode returns the error code carried by a response.failed or error
// event, or "" for any other event.
func (e streamEvent) failureCode() string {
	switch e.Type {
	case "response.failed":
		if e.Response.Error != nil {
			return e.Response.Error.Code
		}
	case "error":
		if e.Code != "" {
			return e.Code
		}
		if e.Error != nil {
			return e.Error.Code
		}
	}
	return ""
}

// isUsageLimitFailure reports whether code means the selected account cannot
// serve the request now, so another account should be tried.
func isUsageLimitFailure(code string) bool {
	return code == codeUsageLimitExceeded || code == codeUsageUnavailable
}

// peekLeadingFailure reads the start of a successful upstream response until
// its first substantive event. If the stream opens by failing with a ChatGPT
// plan usage-limit code, nothing has reached the client yet, so the caller can
// transparently try another account. prefix holds every byte read and must be
// replayed to the client when no such failure is found.
func peekLeadingFailure(body io.Reader) (prefix []byte, failure string) {
	chunk := make([]byte, 4096)
	for len(prefix) < maxStreamPeek {
		n, err := body.Read(chunk)
		prefix = append(prefix, chunk[:n]...)
		if cannotBeSSE(prefix) {
			return prefix, "" // not a stream; nothing to inspect
		}
		for _, payload := range sseData(prefix, err != nil) {
			var event streamEvent
			if json.Unmarshal(payload, &event) != nil {
				continue
			}
			switch event.Type {
			case "response.created", "response.queued", "response.in_progress", "response.metadata":
				continue // bookkeeping events precede any output or failure
			}
			if code := event.failureCode(); isUsageLimitFailure(code) {
				return prefix, code
			}
			return prefix, ""
		}
		if err != nil {
			return prefix, ""
		}
	}
	return prefix, ""
}

// replayBody returns resp.Body's replacement after peekLeadingFailure: the
// buffered prefix followed by the unread remainder, closing the original.
type replayBody struct {
	io.Reader
	io.Closer
}

func newReplayBody(prefix []byte, rest io.ReadCloser) io.ReadCloser {
	return replayBody{Reader: io.MultiReader(bytes.NewReader(prefix), rest), Closer: rest}
}
