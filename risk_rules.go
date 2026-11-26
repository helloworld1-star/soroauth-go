package soroauth

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"
	"go.yaml.in/yaml/v3"
)

// ConfiguredRule is an interface for a custom risk rule loaded from configuration.
type ConfiguredRule interface {
	// Name returns the unique rule identifier.
	Name() string
	// Evaluate analyzes the authorization entry and returns findings.
	Evaluate(entry xdr.SorobanAuthorizationEntry) ([]Finding, error)
}

// BuiltInFindingCodes is the set of finding codes produced by the built-in analyzer.
// Configured rules cannot use or attempt to suppress any of these codes.
var BuiltInFindingCodes = map[string]bool{
	FindingCodeSourceAccountWithDelegates:       true,
	FindingCodeDelegateDepthExceeded:            true,
	FindingCodeDelegateCountHigh:                true,
	FindingCodeSubInvocationCountHigh:           true,
	FindingCodeExpirationFarFuture:              true,
	FindingCodeExpirationZero:                   true,
	FindingCodeContractUnknown:                  true,
	FindingCodeUnsignedDelegates:                true,
	FindingCodeLegacyCredentialsNotAddressBound: true,
}

// RuleDefinition represents the schema of a rule in JSON/YAML configuration.
type RuleDefinition struct {
	Name        string          `json:"name" yaml:"name"`
	Type        string          `json:"type" yaml:"type"`
	Severity    FindingSeverity `json:"severity" yaml:"severity"`
	Code        string          `json:"code" yaml:"code"`
	Title       string          `json:"title" yaml:"title"`
	Description string          `json:"description" yaml:"description"`
	Rationale   string          `json:"rationale" yaml:"rationale"`
	Action      string          `json:"action" yaml:"action"` // e.g. "suppress" or "flag"

	// Type-specific configuration parameters matching policy/rules.go vocabulary:
	AllowedContracts []string `json:"allowed_contracts" yaml:"allowed_contracts"`
	AllowedFunctions []string `json:"allowed_functions" yaml:"allowed_functions"`
	MaxAmount        *uint64  `json:"max_amount" yaml:"max_amount"`
	ForbiddenMethods []string `json:"forbidden_methods" yaml:"forbidden_methods"`
}

// RiskRulesConfig represents a loaded rule set configuration.
type RiskRulesConfig struct {
	Rules []RuleDefinition `json:"rules" yaml:"rules"`
}

// LoadRiskRules parses and validates risk rules from JSON or YAML configuration bytes.
// It fails closed: a malformed rule or an attempt to suppress built-in findings is refused
// naming the offending rule.
func LoadRiskRules(data []byte) ([]ConfiguredRule, error) {
	var cfg RiskRulesConfig

	// Try JSON first; if it doesn't parse, try YAML.
	if err := json.Unmarshal(data, &cfg); err != nil {
		if yamlErr := yaml.Unmarshal(data, &cfg); yamlErr != nil {
			return nil, fmt.Errorf("soroauth: load risk rules: malformed configuration: %w", err)
		}
	}

	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("soroauth: load risk rules: no rules defined in configuration")
	}

	configuredRules := make([]ConfiguredRule, 0, len(cfg.Rules))
	for i, def := range cfg.Rules {
		ruleName := def.Name
		if ruleName == "" {
			ruleName = fmt.Sprintf("rule[%d]", i)
		}

		// Validation check: Action cannot be "suppress" for built-in findings
		if strings.EqualFold(def.Action, "suppress") || strings.EqualFold(def.Type, "suppress") {
			return nil, fmt.Errorf("soroauth: load risk rules: rule %q: suppressing built-in findings is forbidden", ruleName)
		}

		// Validation check: Code cannot collide with or suppress built-in finding codes
		if BuiltInFindingCodes[def.Code] {
			return nil, fmt.Errorf("soroauth: load risk rules: rule %q: cannot use or override built-in finding code %q", ruleName, def.Code)
		}

		rule, err := buildRule(ruleName, def)
		if err != nil {
			return nil, fmt.Errorf("soroauth: load risk rules: rule %q: %w", ruleName, err)
		}
		configuredRules = append(configuredRules, rule)
	}

	return configuredRules, nil
}

func buildRule(name string, def RuleDefinition) (ConfiguredRule, error) {
	severity := def.Severity
	if severity == "" {
		severity = SeverityWarning
	}
	if severity != SeverityCritical && severity != SeverityWarning && severity != SeverityInfo {
		return nil, fmt.Errorf("invalid severity %q", severity)
	}

	code := def.Code
	if code == "" {
		code = strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	}

	switch def.Type {
	case "contract_allowlist":
		if len(def.AllowedContracts) == 0 {
			return nil, fmt.Errorf("contract_allowlist requires non-empty allowed_contracts")
		}
		allowed := make(map[string]bool, len(def.AllowedContracts))
		for _, addr := range def.AllowedContracts {
			if _, err := ParseAddress(addr); err != nil {
				return nil, fmt.Errorf("invalid contract address %q: %w", addr, err)
			}
			allowed[addr] = true
		}
		return &contractAllowlistConfigRule{
			name:        name,
			code:        code,
			severity:    severity,
			title:       def.Title,
			description: def.Description,
			rationale:   def.Rationale,
			allowed:     allowed,
		}, nil

	case "function_allowlist":
		if len(def.AllowedFunctions) == 0 {
			return nil, fmt.Errorf("function_allowlist requires non-empty allowed_functions")
		}
		allowed := make(map[string]bool, len(def.AllowedFunctions))
		for _, fn := range def.AllowedFunctions {
			allowed[fn] = true
		}
		return &functionAllowlistConfigRule{
			name:        name,
			code:        code,
			severity:    severity,
			title:       def.Title,
			description: def.Description,
			rationale:   def.Rationale,
			allowed:     allowed,
		}, nil

	case "max_amount":
		if def.MaxAmount == nil {
			return nil, fmt.Errorf("max_amount requires max_amount parameter")
		}
		return &maxAmountConfigRule{
			name:        name,
			code:        code,
			severity:    severity,
			title:       def.Title,
			description: def.Description,
			rationale:   def.Rationale,
			maxAmount:   *def.MaxAmount,
		}, nil

	case "forbidden_sac_admin":
		forbidden := make(map[string]bool)
		defaultMethods := []string{
			"set_admin", "set_authorized", "set_authorization_entry_ttl",
			"upgrade", "set_contract_id", "set_spec_entries",
		}
		for _, m := range defaultMethods {
			forbidden[m] = true
		}
		for _, m := range def.ForbiddenMethods {
			forbidden[m] = true
		}
		return &forbiddenSACAdminConfigRule{
			name:        name,
			code:        code,
			severity:    severity,
			title:       def.Title,
			description: def.Description,
			rationale:   def.Rationale,
			forbidden:   forbidden,
		}, nil

	default:
		return nil, fmt.Errorf("unknown rule type %q", def.Type)
	}
}

type contractAllowlistConfigRule struct {
	name        string
	code        string
	severity    FindingSeverity
	title       string
	description string
	rationale   string
	allowed     map[string]bool
}

func (r *contractAllowlistConfigRule) Name() string { return r.name }

func (r *contractAllowlistConfigRule) Evaluate(entry xdr.SorobanAuthorizationEntry) ([]Finding, error) {
	var findings []Finding
	err := r.checkInvocation(entry.RootInvocation, "root", &findings)
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func (r *contractAllowlistConfigRule) checkInvocation(inv xdr.SorobanAuthorizedInvocation, path string, findings *[]Finding) error {
	if inv.Function.ContractFn != nil {
		addr := inv.Function.ContractFn.ContractAddress
		if addr.Type == xdr.ScAddressTypeScAddressTypeContract && addr.ContractId != nil {
			contractStr, err := FormatAddress(addr)
			if err != nil {
				return err
			}
			if !r.allowed[contractStr] {
				title := r.title
				if title == "" {
					title = "Contract not in configured allowlist"
				}
				desc := r.description
				if desc == "" {
					desc = fmt.Sprintf("Contract %s called at %s is not permitted by allowlist", contractStr, path)
				}
				*findings = append(*findings, Finding{
					Code:        r.code,
					Severity:    r.severity,
					Title:       title,
					Description: desc,
					Rationale:   r.rationale,
				})
			}
		}
	}
	for i, sub := range inv.SubInvocations {
		if err := r.checkInvocation(sub, fmt.Sprintf("%s/sub[%d]", path, i), findings); err != nil {
			return err
		}
	}
	return nil
}

type functionAllowlistConfigRule struct {
	name        string
	code        string
	severity    FindingSeverity
	title       string
	description string
	rationale   string
	allowed     map[string]bool
}

func (r *functionAllowlistConfigRule) Name() string { return r.name }

func (r *functionAllowlistConfigRule) Evaluate(entry xdr.SorobanAuthorizationEntry) ([]Finding, error) {
	var findings []Finding
	err := r.checkInvocation(entry.RootInvocation, "root", &findings)
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func (r *functionAllowlistConfigRule) checkInvocation(inv xdr.SorobanAuthorizedInvocation, path string, findings *[]Finding) error {
	if inv.Function.ContractFn != nil {
		fn := string(inv.Function.ContractFn.FunctionName)
		if !r.allowed[fn] {
			title := r.title
			if title == "" {
				title = "Function not in configured allowlist"
			}
			desc := r.description
			if desc == "" {
				desc = fmt.Sprintf("Function %q called at %s is not permitted by allowlist", fn, path)
			}
			*findings = append(*findings, Finding{
				Code:        r.code,
				Severity:    r.severity,
				Title:       title,
				Description: desc,
				Rationale:   r.rationale,
			})
		}
	}
	for i, sub := range inv.SubInvocations {
		if err := r.checkInvocation(sub, fmt.Sprintf("%s/sub[%d]", path, i), findings); err != nil {
			return err
		}
	}
	return nil
}

type maxAmountConfigRule struct {
	name        string
	code        string
	severity    FindingSeverity
	title       string
	description string
	rationale   string
	maxAmount   uint64
}

func (r *maxAmountConfigRule) Name() string { return r.name }

func (r *maxAmountConfigRule) Evaluate(entry xdr.SorobanAuthorizationEntry) ([]Finding, error) {
	var findings []Finding
	err := r.checkInvocationArgs(entry.RootInvocation, "root", &findings)
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func (r *maxAmountConfigRule) checkInvocationArgs(inv xdr.SorobanAuthorizedInvocation, path string, findings *[]Finding) error {
	if inv.Function.ContractFn != nil {
		for i, arg := range inv.Function.ContractFn.Args {
			r.checkScVal(arg, fmt.Sprintf("%s/arg[%d]", path, i), findings)
		}
	}
	for i, sub := range inv.SubInvocations {
		if err := r.checkInvocationArgs(sub, fmt.Sprintf("%s/sub[%d]", path, i), findings); err != nil {
			return err
		}
	}
	return nil
}

func (r *maxAmountConfigRule) checkScVal(val xdr.ScVal, location string, findings *[]Finding) {
	exceeded := false
	var amount uint64
	switch val.Type {
	case xdr.ScValTypeScvU64:
		if val.U64 != nil && uint64(*val.U64) > r.maxAmount {
			exceeded = true
			amount = uint64(*val.U64)
		}
	case xdr.ScValTypeScvI64:
		if val.I64 != nil && *val.I64 > 0 && uint64(*val.I64) > r.maxAmount {
			exceeded = true
			amount = uint64(*val.I64)
		}
	case xdr.ScValTypeScvU128:
		if val.U128 != nil {
			hi, lo := val.U128.Hi, val.U128.Lo
			if hi > 0 || uint64(lo) > r.maxAmount {
				exceeded = true
				amount = uint64(lo)
			}
		}
	case xdr.ScValTypeScvI128:
		if val.I128 != nil {
			hi, lo := val.I128.Hi, val.I128.Lo
			if hi > 0 || (hi == 0 && lo > 0 && uint64(lo) > r.maxAmount) {
				exceeded = true
				amount = uint64(lo)
			}
		}
	case xdr.ScValTypeScvVec:
		if val.Vec != nil && *val.Vec != nil {
			for i, elem := range **val.Vec {
				r.checkScVal(elem, fmt.Sprintf("%s/vec[%d]", location, i), findings)
			}
		}
	case xdr.ScValTypeScvMap:
		if val.Map != nil && *val.Map != nil {
			for i, kv := range **val.Map {
				r.checkScVal(kv.Val, fmt.Sprintf("%s/map[%d]", location, i), findings)
			}
		}
	}

	if exceeded {
		title := r.title
		if title == "" {
			title = "Amount exceeds configured threshold"
		}
		desc := r.description
		if desc == "" {
			desc = fmt.Sprintf("Amount %d exceeds maximum allowed %d at %s", amount, r.maxAmount, location)
		}
		*findings = append(*findings, Finding{
			Code:        r.code,
			Severity:    r.severity,
			Title:       title,
			Description: desc,
			Rationale:   r.rationale,
		})
	}
}

type forbiddenSACAdminConfigRule struct {
	name        string
	code        string
	severity    FindingSeverity
	title       string
	description string
	rationale   string
	forbidden   map[string]bool
}

func (r *forbiddenSACAdminConfigRule) Name() string { return r.name }

func (r *forbiddenSACAdminConfigRule) Evaluate(entry xdr.SorobanAuthorizationEntry) ([]Finding, error) {
	var findings []Finding
	err := r.checkInvocation(entry.RootInvocation, "root", &findings)
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func (r *forbiddenSACAdminConfigRule) checkInvocation(inv xdr.SorobanAuthorizedInvocation, path string, findings *[]Finding) error {
	if inv.Function.ContractFn != nil {
		fn := string(inv.Function.ContractFn.FunctionName)
		if r.forbidden[fn] {
			title := r.title
			if title == "" {
				title = "Forbidden admin method invoked"
			}
			desc := r.description
			if desc == "" {
				desc = fmt.Sprintf("Forbidden method %q called at %s", fn, path)
			}
			*findings = append(*findings, Finding{
				Code:        r.code,
				Severity:    r.severity,
				Title:       title,
				Description: desc,
				Rationale:   r.rationale,
			})
		}
	}
	for i, sub := range inv.SubInvocations {
		if err := r.checkInvocation(sub, fmt.Sprintf("%s/sub[%d]", path, i), findings); err != nil {
			return err
		}
	}
	return nil
}
