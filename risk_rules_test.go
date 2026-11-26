package soroauth

import (
	"strings"
	"testing"
)

func TestLoadRiskRules_ValidJSON(t *testing.T) {
	jsonConfig := []byte(`{
		"rules": [
			{
				"name": "corporate_contracts",
				"type": "contract_allowlist",
				"severity": "critical",
				"code": "OUTSIDE_CORPORATE_ALLOWLIST",
				"title": "Unapproved contract",
				"description": "Calls unapproved contract",
				"rationale": "Only approved contracts may be called",
				"allowed_contracts": ["CA6XPIBW3YXBR4RES2AWM4ASO7RZDF2MRVCP35W2XZ2XWBQ6X4IPS6A2"]
			},
			{
				"name": "transfer_cap",
				"type": "max_amount",
				"severity": "warning",
				"code": "TRANSFER_CAP_EXCEEDED",
				"max_amount": 1000000000
			}
		]
	}`)

	rules, err := LoadRiskRules(jsonConfig)
	if err != nil {
		t.Fatalf("unexpected error loading valid JSON rules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Name() != "corporate_contracts" {
		t.Errorf("expected first rule name 'corporate_contracts', got %q", rules[0].Name())
	}
}

func TestLoadRiskRules_ValidYAML(t *testing.T) {
	yamlConfig := []byte(`
rules:
  - name: function_limits
    type: function_allowlist
    severity: warning
    allowed_functions:
      - transfer
      - approve
`)

	rules, err := LoadRiskRules(yamlConfig)
	if err != nil {
		t.Fatalf("unexpected error loading valid YAML rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name() != "function_limits" {
		t.Errorf("expected rule name 'function_limits', got %q", rules[0].Name())
	}
}

func TestLoadRiskRules_MalformedConfigNamesOffendingRule(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		expectedErr string
	}{
		{
			name: "unknown rule type",
			config: `{
				"rules": [
					{"name": "bad_rule", "type": "quantum_check"}
				]
			}`,
			expectedErr: `rule "bad_rule"`,
		},
		{
			name: "invalid contract address",
			config: `{
				"rules": [
					{
						"name": "broken_allowlist",
						"type": "contract_allowlist",
						"allowed_contracts": ["not-a-valid-address"]
					}
				]
			}`,
			expectedErr: `rule "broken_allowlist"`,
		},
		{
			name: "missing max_amount value",
			config: `{
				"rules": [
					{
						"name": "missing_amount",
						"type": "max_amount"
					}
				]
			}`,
			expectedErr: `rule "missing_amount"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadRiskRules([]byte(tt.config))
			if err == nil {
				t.Fatalf("expected error for malformed rule, got nil")
			}
			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("expected error to contain %q, got %q", tt.expectedErr, err.Error())
			}
		})
	}
}

func TestLoadRiskRules_CannotSuppressBuiltInFinding(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "action suppress",
			config: `{
				"rules": [
					{
						"name": "override_delegates",
						"action": "suppress",
						"code": "DELEGATE_DEPTH_EXCEEDED"
					}
				]
			}`,
		},
		{
			name: "built-in finding code collision",
			config: `{
				"rules": [
					{
						"name": "hijack_code",
						"type": "max_amount",
						"code": "EXPIRATION_ZERO",
						"max_amount": 500
					}
				]
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadRiskRules([]byte(tt.config))
			if err == nil {
				t.Fatalf("expected load error preventing suppression of built-in finding, got nil")
			}
			if !strings.Contains(err.Error(), "cannot use or override built-in finding code") &&
				!strings.Contains(err.Error(), "suppressing built-in findings is forbidden") {
				t.Errorf("unexpected error message: %v", err)
			}
		})
	}
}

func TestAnalyze_WithCustomRules(t *testing.T) {
	entry := loadVectorEntry(t, "v2_single_testnet")

	// Create a rule that flags contract not in allowlist
	cfgBytes := []byte(`{
		"rules": [
			{
				"name": "restrict_contract",
				"type": "contract_allowlist",
				"code": "CONTRACT_FORBIDDEN",
				"severity": "critical",
				"allowed_contracts": ["CA6XPIBW3YXBR4RES2AWM4ASO7RZDF2MRVCP35W2XZ2XWBQ6X4IPS6A2"]
			}
		]
	}`)
	customRules, err := LoadRiskRules(cfgBytes)
	if err != nil {
		t.Fatalf("failed to load rules: %v", err)
	}

	riskCfg := DefaultRiskConfig()
	riskCfg.CustomRules = customRules

	findings, err := Analyze(entry, &riskCfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	var foundCustom bool
	for _, f := range findings {
		if f.Code == "CONTRACT_FORBIDDEN" {
			foundCustom = true
			if f.Severity != SeverityCritical {
				t.Errorf("expected critical severity, got %v", f.Severity)
			}
		}
	}
	if !foundCustom {
		t.Errorf("expected custom finding CONTRACT_FORBIDDEN to be evaluated")
	}
}
