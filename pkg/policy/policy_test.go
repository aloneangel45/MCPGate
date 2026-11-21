package policy

import (
	"path/filepath"
	"testing"
)

func TestPresetsValid(t *testing.T) {
	for _, name := range []string{"strict", "balanced", "readonly", "airgapped"} {
		p, err := Preset(name)
		if err != nil {
			t.Fatalf("Preset(%q) failed: %v", name, err)
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("Preset(%q).Validate() failed: %v", name, err)
		}
	}
	if _, err := Preset("invalid"); err == nil {
		t.Fatalf("expected error for invalid preset")
	}
}

func TestEvaluateToolPrecedence(t *testing.T) {
	p, _ := Preset("balanced")
	p.MCP.AllowTools = []string{"git_*"}
	p.MCP.PromptTools = []string{"git_push*"}
	p.MCP.DenyTools = []string{"git_push_force"}

	if d := p.EvaluateTool("git_push_force"); d.Action != ActionDeny {
		t.Fatalf("expected deny for git_push_force, got %+v", d)
	}
	if d := p.EvaluateTool("git_push_origin"); d.Action != ActionPrompt {
		t.Fatalf("expected prompt for git_push_origin, got %+v", d)
	}
	if d := p.EvaluateTool("git_status"); d.Action != ActionAllow {
		t.Fatalf("expected allow for git_status, got %+v", d)
	}
}

func TestEvaluatePathSecurityAndTraversal(t *testing.T) {
	dir := t.TempDir()
	p, _ := Preset("strict")
	p.Filesystem.AllowPaths = []string{dir}

	if d := p.EvaluatePath(filepath.Join(dir, "main.go"), dir); d.Action != ActionAllow {
		t.Fatalf("expected workspace file allowed, got %+v", d)
	}
	if d := p.EvaluatePath("~/.ssh/id_rsa", dir); d.Action != ActionDeny {
		t.Fatalf("expected ~/.ssh/id_rsa denied, got %+v", d)
	}
	if d := p.EvaluatePath(filepath.Join(dir, ".env.production"), dir); d.Action != ActionDeny {
		t.Fatalf("expected .env.production denied, got %+v", d)
	}
	if d := p.EvaluatePath(filepath.Join(dir, "..", "outside.txt"), dir); d.Action != ActionDeny {
		t.Fatalf("expected parent traversal denied, got %+v", d)
	}
}

func TestEvaluateDomainRules(t *testing.T) {
	p, _ := Preset("strict")
	p.Network.AllowDomains = []string{"api.github.com", "*.openai.com"}
	p.Network.DenyDomains = []string{"evil.openai.com"}

	if d := p.EvaluateDomain("api.github.com", 443); d.Action != ActionAllow {
		t.Fatalf("expected api.github.com:443 allowed, got %+v", d)
	}
	if d := p.EvaluateDomain("api.openai.com", 443); d.Action != ActionAllow {
		t.Fatalf("expected wildcard subdomain allowed, got %+v", d)
	}
	if d := p.EvaluateDomain("evil.openai.com", 443); d.Action != ActionDeny {
		t.Fatalf("expected explicit deny to override wildcard allow, got %+v", d)
	}
	if d := p.EvaluateDomain("api.github.com", 80); d.Action != ActionDeny {
		t.Fatalf("expected non-443 port denied in strict preset, got %+v", d)
	}
	if d := p.EvaluateDomain("attacker.xyz", 443); d.Action != ActionDeny {
		t.Fatalf("expected non-allowlisted domain denied in strict preset, got %+v", d)
	}

	air, _ := Preset("airgapped")
	if d := air.EvaluateDomain("api.github.com", 443); d.Action != ActionDeny {
		t.Fatalf("expected airgapped preset to deny all domains, got %+v", d)
	}
}

func TestParseYAMLWithPresetOverride(t *testing.T) {
	raw := []byte(`
version: mcpgate/v1
preset: strict
network:
  allow_domains:
    - api.github.com
mcp:
  max_calls_per_minute: 45
`)
	p, err := ParseYAML(raw)
	if err != nil {
		t.Fatalf("ParseYAML failed: %v", err)
	}
	if p.MCP.DefaultToolAction != ActionDeny || p.MCP.MaxCallsPerMinute != 45 {
		t.Fatalf("unexpected parsed policy: %+v", p.MCP)
	}
	if d := p.EvaluateDomain("api.github.com", 443); d.Action != ActionAllow {
		t.Fatalf("expected allowlisted domain allowed, got %+v", d)
	}
}

