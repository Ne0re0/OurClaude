package main

import (
	"strings"
	"testing"
)

func TestCodexProviderArgs(t *testing.T) {
	cfg := &Config{ServerURL: "https://proxy.example/"}
	args := codexProviderArgs(cfg, []string{"exec", "hello"})

	if len(args) != 6 {
		t.Fatalf("got %d arguments, want 6: %#v", len(args), args)
	}
	if args[0] != "-c" || args[1] != `model_provider="ourcodex"` {
		t.Fatalf("missing model provider override: %#v", args)
	}
	provider := args[3]
	for _, want := range []string{
		`base_url = "https://proxy.example/proxy/v1"`,
		`env_key = "OURCODEX_API_KEY"`,
		`wire_api = "responses"`,
		`requires_openai_auth = false`,
		`supports_websockets = false`,
	} {
		if !strings.Contains(provider, want) {
			t.Errorf("provider override %q does not contain %q", provider, want)
		}
	}
	if args[4] != "exec" || args[5] != "hello" {
		t.Fatalf("user arguments were not preserved: %#v", args)
	}
}
