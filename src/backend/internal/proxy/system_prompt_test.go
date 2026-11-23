package proxy

import (
	"encoding/json"
	"testing"
)

const testPrefix = `Your name is "Foobar", act nice as santa`

func systemBlocks(t *testing.T, body []byte) []map[string]interface{} {
	t.Helper()
	var req struct {
		System []map[string]interface{} `json:"system"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("system is not a block array: %v\n%s", err, body)
	}
	return req.System
}

func TestInjectSystemPromptClaudeCodeArray(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-5","max_tokens":32000,"system":[
		{"type":"text","text":"x-anthropic-billing-header: cc_version=2.0; cc_entrypoint=cli;"},
		{"type":"text","text":"You are Claude Code, Anthropic's official CLI for Claude.","cache_control":{"type":"ephemeral"}},
		{"type":"text","text":"Main instructions","cache_control":{"type":"ephemeral"}}
	],"messages":[{"role":"user","content":"hi"}]}`)

	blocks := systemBlocks(t, injectSystemPrompt(body, testPrefix))
	if len(blocks) != 4 {
		t.Fatalf("want 4 blocks, got %d: %v", len(blocks), blocks)
	}
	if blocks[1]["text"] != "You are Claude Code, Anthropic's official CLI for Claude." {
		t.Errorf("identity block moved: %v", blocks[1])
	}
	if blocks[2]["text"] != testPrefix {
		t.Errorf("injected block not after identity: %v", blocks[2])
	}
	if blocks[3]["text"] != "Main instructions" || blocks[3]["cache_control"] == nil {
		t.Errorf("original block or its cache_control lost: %v", blocks[3])
	}
}

func TestInjectSystemPromptPlainArray(t *testing.T) {
	body := []byte(`{"system":[{"type":"text","text":"Be brief."}]}`)
	blocks := systemBlocks(t, injectSystemPrompt(body, testPrefix))
	if len(blocks) != 2 || blocks[0]["text"] != testPrefix || blocks[1]["text"] != "Be brief." {
		t.Fatalf("unexpected blocks: %v", blocks)
	}
}

func TestInjectSystemPromptString(t *testing.T) {
	blocks := systemBlocks(t, injectSystemPrompt([]byte(`{"system":"Be brief."}`), testPrefix))
	if len(blocks) != 2 || blocks[0]["text"] != testPrefix || blocks[1]["text"] != "Be brief." {
		t.Fatalf("unexpected blocks: %v", blocks)
	}
}

func TestInjectSystemPromptMissing(t *testing.T) {
	blocks := systemBlocks(t, injectSystemPrompt([]byte(`{"max_tokens":10}`), testPrefix))
	if len(blocks) != 1 || blocks[0]["text"] != testPrefix {
		t.Fatalf("unexpected blocks: %v", blocks)
	}
}

func TestInjectSystemPromptInvalidJSON(t *testing.T) {
	in := []byte(`not json`)
	if got := injectSystemPrompt(in, testPrefix); string(got) != string(in) {
		t.Fatalf("invalid body was modified: %s", got)
	}
}
