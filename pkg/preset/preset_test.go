package preset

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestResolveIDEConfigCrossPlatform(t *testing.T) {
	winEnv := map[string]string{
		"USERPROFILE": `C:\Users\Alice`,
		"APPDATA":     `C:\Users\Alice\AppData\Roaming`,
	}
	macEnv := map[string]string{
		"HOME": "/Users/alice",
	}
	linuxEnv := map[string]string{
		"HOME":            "/home/alice",
		"XDG_CONFIG_HOME": "/home/alice/.xdg",
	}

	lookup := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	cases := []struct {
		ide     string
		goos    string
		env     map[string]string
		wantSub string
		wantKey string
	}{
		{"claude", "windows", winEnv, `AppData\Roaming\Claude\claude_desktop_config.json`, "mcpServers"},
		{"claude", "darwin", macEnv, "/Users/alice/Library/Application Support/Claude/claude_desktop_config.json", "mcpServers"},
		{"claude", "linux", linuxEnv, "/home/alice/.xdg/Claude/claude_desktop_config.json", "mcpServers"},
		{"claude-code", "linux", linuxEnv, "/home/alice/.claude.json", "mcpServers"},
		{"cursor", "darwin", macEnv, "/Users/alice/.cursor/mcp.json", "mcpServers"},
		{"vscode", "windows", winEnv, `AppData\Roaming\Code\User\mcp.json`, "servers"},
		{"vscode", "darwin", macEnv, "/Users/alice/Library/Application Support/Code/User/mcp.json", "servers"},
		{"vscode", "linux", linuxEnv, "/home/alice/.xdg/Code/User/mcp.json", "servers"},
		{"windsurf", "linux", linuxEnv, "/home/alice/.codeium/windsurf/mcp_config.json", "mcpServers"},
		{"zed", "windows", winEnv, `AppData\Roaming\Zed\settings.json`, "context_servers"},
		{"zed", "linux", linuxEnv, "/home/alice/.xdg/zed/settings.json", "context_servers"},
	}

	for _, tc := range cases {
		cfg, err := ResolveIDEConfigFor(tc.ide, tc.goos, lookup(tc.env))
		if err != nil {
			t.Fatalf("ResolveIDEConfigFor(%s, %s) failed: %v", tc.ide, tc.goos, err)
		}
		if cfg.ServerKey != tc.wantKey {
			t.Errorf("%s/%s: ServerKey = %q, want %q", tc.ide, tc.goos, cfg.ServerKey, tc.wantKey)
		}
		if !strings.HasSuffix(cfg.Path, tc.wantSub) {
			t.Errorf("%s/%s: Path = %q, want suffix %q", tc.ide, tc.goos, cfg.Path, tc.wantSub)
		}
	}

	if _, err := ResolveIDEConfig("unknown-editor"); err == nil {
		t.Fatal("expected error for unsupported IDE")
	}
}

func TestDiscoverIDEConfigsHermetic(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	appData := filepath.Join(tmp, "appdata")
	xdg := filepath.Join(tmp, "xdg")

	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", appData)
	t.Setenv("XDG_CONFIG_HOME", xdg)

	// Create Cursor and Claude Desktop configs on disk.
	cursorCfg, err := ResolveIDEConfig("cursor")
	if err != nil {
		t.Fatalf("resolve cursor: %v", err)
	}
	claudeCfg, err := ResolveIDEConfig("claude")
	if err != nil {
		t.Fatalf("resolve claude: %v", err)
	}

	for _, p := range []string{cursorCfg.Path, claudeCfg.Path} {
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		if err := os.WriteFile(p, []byte(`{"mcpServers":{}}`), 0600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	found := DiscoverIDEConfigs()
	if len(found) != 2 {
		t.Fatalf("DiscoverIDEConfigs() returned %d configs (%+v), want 2 (GOOS=%s)", len(found), found, runtime.GOOS)
	}

	ids := map[string]bool{}
	for _, f := range found {
		if !f.Exists {
			t.Errorf("discovered config %s has Exists=false", f.ID)
		}
		ids[f.ID] = true
	}
	if !ids["cursor"] || !ids["claude"] {
		t.Errorf("expected cursor and claude to be discovered, got %+v", ids)
	}
}

func TestStripJSONCPreservesURLsAndEscapes(t *testing.T) {
	raw := []byte(`{
  // Top-level comment
  "url": "https://example.com/api/*not-a-comment*///still-string",
  "escaped": "quote \"// inside\" end",
  /* Multi-line
     block comment */
  "list": [
    "one",
    "two", // trailing comma next
  ],
}`)
	cleaned := StripJSONC(raw)
	var doc map[string]any
	if err := json.Unmarshal(cleaned, &doc); err != nil {
		t.Fatalf("StripJSONC produced invalid JSON: %v\n%s", err, string(cleaned))
	}
	if got := doc["url"]; got != "https://example.com/api/*not-a-comment*///still-string" {
		t.Fatalf("url corrupted: %q", got)
	}
	if got := doc["escaped"]; got != `quote "// inside" end` {
		t.Fatalf("escaped string corrupted: %q", got)
	}
}

func TestWrapAndUnwrapRoundTripJSONC(t *testing.T) {
	inputJSONC := []byte(`{
  // Preserve unrelated editor settings!
  "theme": "obsidian-dark",
  "editor.fontSize": 14,
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/workspace"],
      "env": {
        "NODE_ENV": "production",
      },
      "disabled": false,
    },
    "minimal": {
      "command": "my-local-mcp",
    },
    "already": {
      "command": "mcpgate",
      "args": ["run", "--preset", "strict", "--", "uvx", "mcp-server-git==0.6.2"],
    },
    "remote-sse": {
      "url": "https://mcp.example.com/sse", // remote server must be skipped
    },
  },
}`)

	// 1. First Wrap
	wrapped, res1, err := WrapConfig(inputJSONC, WrapOptions{
		BinaryPath: "/usr/local/bin/mcpgate",
		Preset:     "strict",
	})
	if err != nil {
		t.Fatalf("WrapConfig failed: %v", err)
	}
	if !res1.Changed {
		t.Fatalf("expected Changed=true on first wrap")
	}
	if !reflect.DeepEqual(res1.Wrapped, []string{"filesystem", "minimal"}) {
		t.Errorf("Wrapped = %v, want [filesystem minimal]", res1.Wrapped)
	}
	if !reflect.DeepEqual(res1.AlreadyWrapped, []string{"already"}) {
		t.Errorf("AlreadyWrapped = %v, want [already]", res1.AlreadyWrapped)
	}
	if !reflect.DeepEqual(res1.Skipped, []string{"remote-sse"}) {
		t.Errorf("Skipped = %v, want [remote-sse]", res1.Skipped)
	}

	// Verify wrapped JSON structure & preservation of unrelated top-level keys.
	var doc map[string]any
	if err := json.Unmarshal(wrapped, &doc); err != nil {
		t.Fatalf("unmarshal wrapped: %v", err)
	}
	if doc["theme"] != "obsidian-dark" {
		t.Errorf("unrelated top-level key 'theme' lost: %v", doc["theme"])
	}
	if doc["editor.fontSize"] != float64(14) {
		t.Errorf("unrelated top-level key 'editor.fontSize' lost: %v", doc["editor.fontSize"])
	}

	servers := doc["mcpServers"].(map[string]any)
	fsSrv := servers["filesystem"].(map[string]any)
	if fsSrv["command"] != "/usr/local/bin/mcpgate" {
		t.Errorf("filesystem command = %v, want /usr/local/bin/mcpgate", fsSrv["command"])
	}
	wantFSArgs := []string{"run", "--preset", "strict", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/workspace"}
	if got := toStringSlice(fsSrv["args"]); !reflect.DeepEqual(got, wantFSArgs) {
		t.Errorf("filesystem args = %v, want %v", got, wantFSArgs)
	}
	if fsSrv["disabled"] != false {
		t.Errorf("filesystem disabled field lost")
	}

	// 2. Second Wrap must be strictly idempotent!
	wrapped2, res2, err := WrapConfig(wrapped, WrapOptions{
		BinaryPath: "/usr/local/bin/mcpgate",
		Preset:     "strict",
	})
	if err != nil {
		t.Fatalf("second WrapConfig failed: %v", err)
	}
	if res2.Changed {
		t.Errorf("expected Changed=false on idempotent second wrap, got %+v", res2)
	}
	if len(res2.Wrapped) != 0 {
		t.Errorf("expected 0 newly wrapped servers on second run, got %v", res2.Wrapped)
	}
	if len(res2.AlreadyWrapped) != 3 {
		t.Errorf("expected 3 already wrapped servers, got %v", res2.AlreadyWrapped)
	}

	// 3. Unwrap restores original commands cleanly.
	unwrapped, ures, err := UnwrapConfig(wrapped2, UnwrapOptions{})
	if err != nil {
		t.Fatalf("UnwrapConfig failed: %v", err)
	}
	if !ures.Changed {
		t.Fatalf("expected Changed=true on unwrap")
	}
	if !reflect.DeepEqual(ures.Unwrapped, []string{"already", "filesystem", "minimal"}) {
		t.Errorf("Unwrapped = %v, want [already filesystem minimal]", ures.Unwrapped)
	}

	var restored map[string]any
	if err := json.Unmarshal(unwrapped, &restored); err != nil {
		t.Fatalf("unmarshal unwrapped: %v", err)
	}
	if restored["theme"] != "obsidian-dark" {
		t.Errorf("top-level key lost after unwrap")
	}
	rServers := restored["mcpServers"].(map[string]any)
	rFS := rServers["filesystem"].(map[string]any)
	if rFS["command"] != "npx" {
		t.Errorf("restored filesystem command = %v, want npx", rFS["command"])
	}
	wantOrigFSArgs := []string{"-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/workspace"}
	if got := toStringSlice(rFS["args"]); !reflect.DeepEqual(got, wantOrigFSArgs) {
		t.Errorf("restored filesystem args = %v, want %v", got, wantOrigFSArgs)
	}
	rMin := rServers["minimal"].(map[string]any)
	if rMin["command"] != "my-local-mcp" {
		t.Errorf("restored minimal command = %v, want my-local-mcp", rMin["command"])
	}
	if _, hasArgs := rMin["args"]; hasArgs {
		t.Errorf("minimal server should have no args after unwrap, got %v", rMin["args"])
	}
}

func TestWrapSelfMCPModeAndUnwrapRemove(t *testing.T) {
	raw := []byte(`{
  "servers": {
    "existing": {"command": "npx", "args": ["-y", "demo@1.0.0"]}
  }
}`)
	out, res, err := WrapConfig(raw, WrapOptions{
		BinaryPath: "mcpgate",
		SelfMCP:    true,
	})
	if err != nil {
		t.Fatalf("WrapConfig(SelfMCP) failed: %v", err)
	}
	if !res.SelfMCPAdded || !res.Changed || res.ServerKey != "servers" {
		t.Fatalf("unexpected SelfMCP result: %+v", res)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	srvs := doc["servers"].(map[string]any)
	// Existing server must NOT have been altered in SelfMCP mode.
	existing := srvs["existing"].(map[string]any)
	if existing["command"] != "npx" {
		t.Errorf("existing server unexpectedly modified in SelfMCP mode: %+v", existing)
	}
	mg := srvs["mcpgate"].(map[string]any)
	if mg["command"] != "mcpgate" || !reflect.DeepEqual(toStringSlice(mg["args"]), []string{"mcp"}) {
		t.Errorf("unexpected self-MCP entry: %+v", mg)
	}

	// Second SelfMCP run is idempotent.
	_, res2, err := WrapConfig(out, WrapOptions{BinaryPath: "mcpgate", SelfMCP: true})
	if err != nil {
		t.Fatalf("second SelfMCP failed: %v", err)
	}
	if res2.Changed || res2.SelfMCPAdded {
		t.Errorf("expected idempotent SelfMCP, got %+v", res2)
	}

	// Unwrap with RemoveSelfMCP removes the mcpgate entry.
	out3, ures, err := UnwrapConfig(out, UnwrapOptions{RemoveSelfMCP: true})
	if err != nil {
		t.Fatalf("UnwrapConfig(RemoveSelfMCP) failed: %v", err)
	}
	if !ures.SelfMCPRemoved || !ures.Changed {
		t.Fatalf("expected SelfMCPRemoved=true, got %+v", ures)
	}
	var doc3 map[string]any
	_ = json.Unmarshal(out3, &doc3)
	if _, exists := doc3["servers"].(map[string]any)["mcpgate"]; exists {
		t.Errorf("expected mcpgate entry to be removed")
	}
}

func TestWrapAndUnwrapZedContextServers(t *testing.T) {
	zedRaw := []byte(`{
  // Zed settings JSONC
  "vim_mode": true,
  "context_servers": {
    "fs": {
      "command": {
        "path": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "."],
        "env": {"FOO": "bar"},
      },
    },
  },
}`)

	wrapped, res, err := WrapConfig(zedRaw, WrapOptions{BinaryPath: "mcpgate", Preset: "readonly"})
	if err != nil {
		t.Fatalf("Zed WrapConfig failed: %v", err)
	}
	if res.ServerKey != "context_servers" || !res.Changed || len(res.Wrapped) != 1 {
		t.Fatalf("unexpected Zed wrap result: %+v", res)
	}

	// Idempotent second wrap
	_, res2, err := WrapConfig(wrapped, WrapOptions{BinaryPath: "mcpgate", Preset: "readonly"})
	if err != nil {
		t.Fatalf("Zed second wrap failed: %v", err)
	}
	if res2.Changed {
		t.Fatalf("expected Zed second wrap to be idempotent")
	}

	unwrapped, ures, err := UnwrapConfig(wrapped, UnwrapOptions{})
	if err != nil {
		t.Fatalf("Zed unwrap failed: %v", err)
	}
	if !ures.Changed || len(ures.Unwrapped) != 1 {
		t.Fatalf("unexpected Zed unwrap result: %+v", ures)
	}

	var doc map[string]any
	if err := json.Unmarshal(unwrapped, &doc); err != nil {
		t.Fatalf("unmarshal Zed unwrapped: %v", err)
	}
	if doc["vim_mode"] != true {
		t.Errorf("vim_mode lost in Zed settings")
	}
	cmdObj := doc["context_servers"].(map[string]any)["fs"].(map[string]any)["command"].(map[string]any)
	if cmdObj["path"] != "npx" {
		t.Errorf("restored Zed path = %v, want npx", cmdObj["path"])
	}
}

func TestWrapAndUnwrapFileAtomic(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "nested", "mcp.json")

	// SelfMCP creates missing config atomically.
	res, err := WrapFile(cfgPath, WrapOptions{
		BinaryPath: "mcpgate",
		SelfMCP:    true,
	})
	if err != nil {
		t.Fatalf("WrapFile(SelfMCP) failed: %v", err)
	}
	if !res.SelfMCPAdded {
		t.Fatalf("expected SelfMCPAdded=true")
	}

	// Ensure no leftover temp files remain.
	entries, err := os.ReadDir(filepath.Dir(cfgPath))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "mcp.json" {
		t.Fatalf("unexpected files in config dir: %v", entries)
	}

	// UnwrapFile with RemoveSelfMCP.
	ures, err := UnwrapFile(cfgPath, UnwrapOptions{RemoveSelfMCP: true})
	if err != nil {
		t.Fatalf("UnwrapFile failed: %v", err)
	}
	if !ures.SelfMCPRemoved {
		t.Fatalf("expected SelfMCPRemoved=true")
	}
}
