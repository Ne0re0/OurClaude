package handlers

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPatchBinaryOnlyTouchesPlaceholderSlots(t *testing.T) {
	// A bare marker before the real slot must stay untouched: writing after it
	// used to overwrite unrelated strings in the binary.
	bare := []byte("..CLBINTOK:in number of type files,dnsdns,files..")
	data := append(append(append([]byte{}, bare...), keyPlaceholder...), originPlaceholder...)
	data = append(data, "tail"...)

	r := httptest.NewRequest("GET", "/dl/x", nil)
	r.Host = "proxy.example.com"
	r.RemoteAddr = "172.20.0.1:50802"
	r.Header.Set("X-Forwarded-Proto", "https")
	key := strings.Repeat("ab", 16)

	out := patchBinary(data, key, r)
	if len(out) != len(data) || !bytes.HasSuffix(out, []byte("tail")) {
		t.Fatal("patching must not change the binary's size or layout")
	}
	if !bytes.HasPrefix(out, bare) {
		t.Error("bytes after a bare marker were modified")
	}
	if !bytes.Contains(out, []byte("CLBINTOK:"+key)) {
		t.Error("tracking key not written into its slot")
	}
	if !bytes.Contains(out, []byte("CLBINURL:https://proxy.example.com ")) {
		t.Error("origin URL not written into its slot")
	}
	if !bytes.Contains(data, keyPlaceholder) {
		t.Error("the source binary must not be modified in place")
	}
}

func TestPublicServerURL(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "x$(id>/tmp/pwned)"
	if _, ok := publicServerURL(r); ok {
		t.Error("a host with shell syntax must be rejected")
	}

	r.Host = "proxy.example.com:8443"
	r.Header.Set("X-Forwarded-Proto", "https") // from a public peer: not trusted
	if got, ok := publicServerURL(r); !ok || got != "http://proxy.example.com:8443" {
		t.Errorf("publicServerURL = %q, %v", got, ok)
	}
}

func TestInstallScriptQuotesValues(t *testing.T) {
	if got := shellQuote(`a'b$(c)`); got != `'a'\''b$(c)'` {
		t.Errorf("shellQuote = %s", got)
	}
	script := generateInstallScript("https://proxy.example.com", "sk-proxy-abc", map[string]string{"linux-amd64": "/dl/k"}, true)
	for _, want := range []string{"SERVER='https://proxy.example.com'", "TOKEN='sk-proxy-abc'", "rtk/releases/download/v1.2.1/", `sudo -u "$SUDO_USER" -H /usr/local/bin/rtk init`} {
		if !strings.Contains(script, want) {
			t.Errorf("install script is missing %q", want)
		}
	}
	if strings.Contains(script, "refs/heads/master/install.sh") {
		t.Error("install script must not pipe the unpinned RTK installer")
	}
}
