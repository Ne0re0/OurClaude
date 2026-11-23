package proxy

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestAcceptsGzip(t *testing.T) {
	cases := map[string]bool{
		"":                        false,
		"identity":                false,
		"br, zstd":                false,
		"gzip":                    true,
		"gzip, deflate, br, zstd": true,
		"br;q=1.0, GZIP;q=0.5":    true,
		"gzip;q=0":                false,
		"gzip; q=0.000":           false,
		"*":                       true,
	}
	for in, want := range cases {
		if got := acceptsGzip(in); got != want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", in, got, want)
		}
	}
}

func gz(t *testing.T, s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestDecodeBody(t *testing.T) {
	plain := "event: message_start\ndata: {\"type\":\"message_start\"}\n\n"
	if got := string(decodeBody([]byte(plain), "")); got != plain {
		t.Fatalf("identity passthrough changed body")
	}
	if got := string(decodeBody(gz(t, plain), "gzip")); got != plain {
		t.Fatalf("gzip decode = %q", got)
	}
	// Truncated stream (capture limit hit) still yields a decoded prefix.
	big := bytes.Repeat([]byte(plain), 2000)
	z := gz(t, string(big))
	if got := decodeBody(z[:len(z)/2], "gzip"); len(got) == 0 || !bytes.HasPrefix(big, got) {
		t.Fatalf("truncated decode returned %d bytes, not a prefix", len(got))
	}
	// Unknown encoding is returned unchanged.
	if got := decodeBody([]byte("xx"), "br"); string(got) != "xx" {
		t.Fatalf("br should pass through unchanged")
	}
}

func TestParseUsageGzipStream(t *testing.T) {
	sse := "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-5-5\",\"usage\":{\"input_tokens\":12,\"cache_read_input_tokens\":3}}}\r\n\r\n" +
		"event: message_delta\r\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\r\n\r\n"
	body := string(decodeBody(gz(t, sse), "gzip"))
	if !bytes.Contains([]byte(body), []byte("\"input_tokens\":12")) {
		t.Fatalf("decoded stream lost usage data")
	}
}
