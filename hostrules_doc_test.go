package soroauth

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// docTableRows returns the cells of every row of a Markdown table in path
// whose first cell is a backticked identifier, keyed by that identifier.
// Backticks and backslash escapes are dropped, so a cell compares equal to the
// plain string it renders as, whatever escaping prettier applied.
func docTableRows(t *testing.T, path string) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	rows := map[string][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		parts := strings.Split(strings.Trim(line, "|"), "|")
		cells := make([]string, 0, len(parts))
		for _, part := range parts {
			cell := strings.TrimSpace(part)
			cell = strings.ReplaceAll(cell, "`", "")
			cell = strings.ReplaceAll(cell, `\`, "")
			cells = append(cells, cell)
		}
		if _, dup := rows[cells[0]]; dup {
			t.Fatalf("%s lists %s twice", path, cells[0])
		}
		rows[cells[0]] = cells
	}
	return rows
}

// TestHostRulesDocumentMatchesCode is the guard both issues ask for: the
// documented rules and limits, and the enforced ones, cannot diverge.
//
// docs/host-rules.md carries two tables. The rules table must list exactly
// the rules HostRules returns, each with the same offline flag, summary,
// source citation and reason. The limits table must state, for every limit it
// names, the value the code enforces: the constants directly, and the host's
// per-signature maximum delegate depth through the same formula ValidateEntry
// applies.
func TestHostRulesDocumentMatchesCode(t *testing.T) {
	rows := docTableRows(t, "docs/host-rules.md")

	t.Run("rules", func(t *testing.T) {
		for _, rule := range HostRules() {
			cells, ok := rows[rule.ID]
			if !ok {
				t.Errorf("docs/host-rules.md does not list rule %s", rule.ID)
				continue
			}
			if len(cells) != 5 {
				t.Errorf("rule %s row has %d cells, want 5", rule.ID, len(cells))
				continue
			}
			wantOffline := "no"
			if rule.Offline {
				wantOffline = "yes"
			}
			for _, field := range []struct{ name, doc, code string }{
				{"offline", cells[1], wantOffline},
				{"summary", cells[2], rule.Summary},
				{"source", cells[3], rule.Source},
				{"why", cells[4], rule.Why},
			} {
				if field.doc != field.code {
					t.Errorf("rule %s %s:\n  doc:  %q\n  code: %q", rule.ID, field.name, field.doc, field.code)
				}
			}
		}
		known := map[string]bool{}
		for _, rule := range HostRules() {
			known[rule.ID] = true
		}
		for id, cells := range rows {
			if len(cells) == 5 && !known[id] {
				t.Errorf("docs/host-rules.md lists rule %s, which HostRules does not", id)
			}
		}
	})

	t.Run("limits", func(t *testing.T) {
		ed25519Sig, err := Ed25519SignatureScVal(make([]byte, 32), make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		maxDepthFor := func(signature xdr.ScVal) int {
			depth := hostValueDepth(signature, HostDepthLimit)
			k := 0
			for hostDelegateDepthOK(k+1, depth) {
				k++
			}
			return k
		}
		want := map[string]int{
			"HostDepthLimit":                  HostDepthLimit,
			"host-max-delegate-depth-void":    maxDepthFor(xdr.ScVal{Type: xdr.ScValTypeScvVoid}),
			"host-max-delegate-depth-ed25519": maxDepthFor(ed25519Sig),
			"MaxDelegateDepth":                MaxDelegateDepth,
			"MaxDecodeDepth":                  MaxDecodeDepth,
			"MAX_ACCOUNT_SIGNATURES":          maxAccountSignatures,
		}
		for name, value := range want {
			cells, ok := rows[name]
			if !ok {
				t.Errorf("docs/host-rules.md's limits table does not list %s", name)
				continue
			}
			got, err := strconv.Atoi(cells[1])
			if err != nil {
				t.Errorf("%s: value %q is not a number", name, cells[1])
				continue
			}
			if got != value {
				t.Errorf("%s: docs/host-rules.md says %d, the code enforces %d", name, got, value)
			}
		}
	})
}
