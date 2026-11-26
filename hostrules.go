package soroauth

import (
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// MaxDelegateDepth is the deepest CAP-71-01 delegate tree soroauth builds,
// validates or signs. The top-level delegates array is depth 1.
//
// It is one policy, derived from two bounds rather than chosen:
//
//   - The host's bound. A delegate at depth k carrying signature s is accepted
//     only when k + 1 + (host value depth of s) <= HostDepthLimit
//     (RuleDelegateDepth). That allows 98 levels with a Void placeholder and
//     96 with an ed25519 signature, measured against soroban-env-host 30.0.1.
//   - The library's own untrusted-input bound. DecodeAuthorizationEntry refuses
//     XDR nested past MaxDecodeDepth, and go-xdr spends one depth level per
//     delegate level plus a fixed overhead for the entry around it.
//
// MaxDelegateDepth is the largest depth at which a tree whose every node
// carries the deepest signature soroauth's own signers produce (the classic
// account vector of {public_key, signature} maps) still decodes under
// MaxDecodeDepth. It is below the host's limit, so everything soroauth signs
// is accepted by the host's depth rule, and everything soroauth signs can be
// decoded by soroauth again. A tree deeper than this is refused with
// ErrDelegateDepthLimit before any signer is called.
//
// The relationship is asserted by tests: a fully signed tree of exactly this
// depth decodes and one level deeper does not, and the host formula admits it.
// If MaxDecodeDepth ever changes, those tests name the new value.
const MaxDelegateDepth = 54

// Host rule identifiers, as reported in HostRuleError.Rule and listed by
// HostRules. They are stable: a caller may branch on them.
const (
	// RuleDelegateOrder: each delegates array is in strictly ascending address
	// order.
	RuleDelegateOrder = "delegate-order"
	// RuleDelegateUnique: no address repeats within one delegates array.
	RuleDelegateUnique = "delegate-unique"
	// RuleDelegateDepth: the delegate tree fits the host's depth budget, and
	// soroauth's MaxDelegateDepth.
	RuleDelegateDepth = "delegate-depth"
	// RuleValueDepth: every signature and argument value fits the host's depth
	// budget.
	RuleValueDepth = "value-depth"
	// RuleMapKeyOrder: every map's keys are strictly ascending in the host's
	// value order.
	RuleMapKeyOrder = "map-key-order"
	// RuleValueForm: every value is representable as a host value.
	RuleValueForm = "value-form"
	// RuleSymbolForm: every symbol uses only the host's symbol alphabet and
	// fits its length limit.
	RuleSymbolForm = "symbol-form"
	// RuleAddressType: credential and delegate addresses are accounts or
	// contracts; addresses inside values are of a type the host accepts.
	RuleAddressType = "address-type"
	// RuleAccountSignature: a signed classic-account node carries 1 to 20
	// {public_key, signature} maps with strictly ascending public keys.
	RuleAccountSignature = "account-signature"
	// RuleCreateContractAuth: an authorized create-contract call names a Wasm
	// or external-reference executable and an address-based contract ID.
	RuleCreateContractAuth = "create-contract-auth"

	// RuleNonceUnused cannot be checked offline: the nonce must not already be
	// consumed on the ledger.
	RuleNonceUnused = "nonce-unused"
	// RuleExpirationReached cannot be checked offline: the current ledger must
	// not be past the signature expiration ledger.
	RuleExpirationReached = "expiration-not-passed"
	// RuleExpirationTooLate cannot be checked offline: the expiration must not
	// exceed the network's max_live_until_ledger.
	RuleExpirationTooLate = "expiration-not-too-late"
	// RuleAccountWeight cannot be checked offline: each classic signer must
	// belong to the account and the weights must meet its medium threshold.
	RuleAccountWeight = "account-weight"
	// RuleDelegateUse cannot be checked offline: delegates are consumed by
	// the account contract's delegate_auth calls, at most once each.
	RuleDelegateUse = "delegate-use"
	// RuleCallDepth cannot be checked offline: the contract call stack during
	// authentication stays within the host's depth limit.
	RuleCallDepth = "call-depth"
	// RuleResourceLimits cannot be checked offline: the transaction must fit
	// the network's size, instruction and memory limits. This is what bounds
	// a delegate tree's breadth; the host has no count limit of its own.
	RuleResourceLimits = "resource-limits"
)

// HostRule is one rule the Soroban host enforces on an authorization entry,
// with where in the host it is enforced.
type HostRule struct {
	// ID is the stable rule identifier, one of the Rule… constants.
	ID string
	// Summary states the rule in one sentence.
	Summary string
	// Source cites the rs-soroban-env file and lines that enforce it, read at
	// soroban-env-host 30.0.1 (soroban-env-common 30.0.1 where it says so).
	Source string
	// Offline reports whether ValidateEntry checks the rule. A rule that
	// depends on ledger state, network configuration or contract behaviour
	// cannot be decided from the entry alone, and is listed so the list is
	// complete rather than silently shorter.
	Offline bool
	// Why says, for a rule that is not checked offline, what it depends on.
	Why string
}

// hostRules is the enumeration. docs/host-rules.md renders the same list, and
// TestHostRulesDocumentMatchesCode fails if the two ever disagree.
var hostRules = []HostRule{
	{
		ID:      RuleDelegateOrder,
		Summary: "Each delegates array, at every depth, is in strictly ascending address order.",
		Source:  "soroban-env-host/src/auth.rs:2163-2193 (DelegatedAccountAuthSignerTreeNode::from_xdr); ScAddress order: host/comparison.rs:193",
		Offline: true,
	},
	{
		ID:      RuleDelegateUnique,
		Summary: "No address repeats within one delegates array; the same address at different depths is allowed.",
		Source:  "soroban-env-host/src/auth.rs:2176-2183",
		Offline: true,
	},
	{
		ID:      RuleDelegateDepth,
		Summary: "A delegate at depth k with signature s needs k + 1 + depth(s) <= 100; soroauth also caps k at MaxDelegateDepth (54).",
		Source:  "soroban-env-host/src/auth.rs:2163, 2197 and 2209; host/conversion.rs:432-441; budget/limits.rs:41 and 83-93",
		Offline: true,
	},
	{
		ID:      RuleValueDepth,
		Summary: "Every signature, argument and constructor argument value has depth(v) <= 100 when converted at the top of the host's budget.",
		Source:  "soroban-env-host/src/host/conversion.rs:432-441 and 549-565; auth.rs:809, 2437, 2446 and 2457; account_contract.rs:111",
		Offline: true,
	},
	{
		ID:      RuleMapKeyOrder,
		Summary: "Every map's keys are strictly ascending in the host's value order (derived Ord of ScVal), so no key repeats.",
		Source:  "soroban-env-host/src/host/metered_map.rs:128-136; host/comparison.rs:298-376 and 655; host/conversion.rs:556-565",
		Offline: true,
	},
	{
		ID:      RuleValueForm,
		Summary: "No vec or map without a body, and no ContractInstance, LedgerKeyContractInstance or LedgerKeyNonce value.",
		Source:  "soroban-env-common/src/val.rs:602-640 (Val::can_represent_scval); soroban-env-common/src/convert.rs:589-600",
		Offline: true,
	},
	{
		ID:      RuleSymbolForm,
		Summary: "Every symbol, including each invoked function name, is at most 32 bytes of [A-Za-z0-9_].",
		Source:  "soroban-env-host/src/host_object.rs:294-314; soroban-env-common/src/symbol.rs:237-246; auth.rs:808",
		Offline: true,
	},
	{
		ID:      RuleAddressType,
		Summary: "Credential and delegate addresses are G accounts or C contracts; an address value is an account, contract or muxed account.",
		Source:  "soroban-env-host/src/auth.rs:2769-2774 and 1098-1104; host/conversion.rs:624-641",
		Offline: true,
	},
	{
		ID:      RuleAccountSignature,
		Summary: "A signed classic-account node carries 1 to 20 {public_key, signature} maps with strictly ascending public keys.",
		Source:  "soroban-env-host/src/builtin_contracts/account_contract.rs:25, 64-67 and 181-213",
		Offline: true,
	},
	{
		ID:      RuleCreateContractAuth,
		Summary: "An authorized create-contract call names a Wasm or external-reference executable and an address-based contract ID preimage.",
		Source:  "soroban-env-host/src/builtin_contracts/account_contract.rs:82-104, built for every authentication at auth.rs:2749-2750",
		Offline: true,
	},
	{
		ID:      RuleNonceUnused,
		Summary: "The (address, nonce) pair has not been consumed before.",
		Source:  "soroban-env-host/src/auth.rs:3058-3063",
		Why:     "needs ledger state",
	},
	{
		ID:      RuleExpirationReached,
		Summary: "The current ledger is not past the signature expiration ledger.",
		Source:  "soroban-env-host/src/auth.rs:2663-2673",
		Why:     "needs the current ledger",
	},
	{
		ID:      RuleExpirationTooLate,
		Summary: "The signature expiration ledger does not exceed max_live_until_ledger.",
		Source:  "soroban-env-host/src/auth.rs:2675-2686",
		Why:     "needs the network's state archival settings",
	},
	{
		ID:      RuleAccountWeight,
		Summary: "Each classic signer belongs to the account and the summed weights meet its medium threshold.",
		Source:  "soroban-env-host/src/builtin_contracts/account_contract.rs:224-263",
		Why:     "needs the account's ledger entry",
	},
	{
		ID:      RuleDelegateUse,
		Summary: "A delegate is matched only by the account contract's delegate_auth call for it, at most once per frame, and must carry a signature when matched.",
		Source:  "soroban-env-host/src/auth.rs:1070-1080 and 2316-2356",
		Why:     "depends on what the account contract's __check_auth does at run time",
	},
	{
		ID:      RuleCallDepth,
		Summary: "The contract call stack during authentication, including nested delegated authentication, stays within the host depth limit.",
		Source:  "soroban-env-host/src/host/frame.rs:476",
		Why:     "depends on the call stack at the moment of authentication",
	},
	{
		ID:      RuleResourceLimits,
		Summary: "The transaction fits the network's size, instruction and memory limits; the host has no count limit on delegates per array.",
		Source:  "soroban-env-host/src/auth.rs:2164 and 2205-2211 walk every delegate with no count check; each node is metered",
		Why:     "the limits are network configuration settings",
	},
}

// HostRules returns every rule the Soroban host enforces on an authorization
// entry that this library knows of, each with its source citation, in the
// order docs/host-rules.md lists them.
//
// Why it exists: the ordering and canonical-form rules used to be checked
// wherever someone had noticed one, so nobody could say whether the set was
// complete, and a missed rule is an entry that fails on chain after fees. The
// list is the enumeration; ValidateEntry is the one place that checks every
// rule marked Offline. A rule that depends on ledger state, network settings
// or contract behaviour is listed with Offline false and the reason, never
// omitted.
//
// The returned slice is a copy; modifying it changes nothing.
func HostRules() []HostRule {
	return append([]HostRule(nil), hostRules...)
}

// HostRuleError reports the host rule an entry breaks and where.
//
// It unwraps to ErrHostRuleViolation and, when the violation also has a more
// specific sentinel, to that one too: ErrDelegateDepthLimit for
// RuleDelegateDepth, ErrDuplicateDelegate (through *DuplicateDelegateError) for
// RuleDelegateUnique, and ErrTooManySignatures for an account signature with
// more than 20 entries. A tree deeper than MaxDelegateDepth also matches
// ErrDecodeLimit, because MaxDelegateDepth is the decode bound expressed in
// delegate levels and that is the sentinel such a tree was refused with before
// MaxDelegateDepth existed.
type HostRuleError struct {
	// Rule is the violated rule's ID, one of the Rule… constants.
	Rule string
	// Path locates the offending node or value, using the CredentialNodes
	// scheme for credential nodes ("credentials",
	// "credentials.delegates[G…].nested[G…]") and "root_invocation…" for the
	// invocation tree.
	Path string
	// Detail describes the violation.
	Detail string

	errs []error
}

// Error implements error.
func (e *HostRuleError) Error() string {
	if len(e.errs) > 0 {
		return fmt.Sprintf("%s: %s", e.Detail, e.errs[0])
	}
	return e.Detail
}

// Unwrap lets errors.Is and errors.As reach ErrHostRuleViolation and any more
// specific sentinel or typed error the violation carries.
func (e *HostRuleError) Unwrap() []error {
	return append([]error{ErrHostRuleViolation}, e.errs...)
}

// maxMessagePath is how much of a path an error message quotes. A path into a
// tree near MaxDelegateDepth names every address on the way down and runs to
// kilobytes; the message keeps its tail, where the violation is, and the full
// path stays available as HostRuleError.Path.
const maxMessagePath = 240

func ruleError(rule, path, detail string, errs ...error) *HostRuleError {
	if len(path) > maxMessagePath && strings.HasPrefix(detail, path) {
		detail = "…" + path[len(path)-maxMessagePath:] + detail[len(path):]
	}
	return &HostRuleError{Rule: rule, Path: path, Detail: detail, errs: errs}
}

// checkDelegateTreeDepth applies RuleDelegateDepth alone to every delegate in
// a tree. WithDelegates uses it: the tree it has just built must fit the depth
// rule with whatever signatures the caller supplied, but a supplied signature's
// shape is checked when the entry is signed, by ValidateEntry, not here.
func checkDelegateTreeDepth(nodes []xdr.SorobanDelegateSignature, parentPath string, depth int) error {
	for i := range nodes {
		label, err := FormatAddress(nodes[i].Address)
		if err != nil {
			label = fmt.Sprintf("#%d", i)
		}
		path := parentPath + ".delegates[" + label + "]"
		if depth > 1 {
			path = parentPath + ".nested[" + label + "]"
		}
		if err := checkDelegateDepth(depth, nodes[i].Signature, path); err != nil {
			return err
		}
		if err := checkDelegateTreeDepth(nodes[i].NestedDelegates, path, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// ValidateEntry checks an authorization entry against every host rule that
// can be decided from the entry alone, and returns the first violation as a
// *HostRuleError.
//
// It is the single validation entry point. AuthorizeEntry and StreamingSign
// call it before any signer runs, so a remote or hardware signer is never
// asked to sign an entry the host would refuse, and again on the signed result,
// so a signature whose own shape breaks a rule (too deep, unordered keys, an
// unsorted multisig vector) is discarded rather than returned. HostRules lists
// what it checks, with citations, and what it cannot check offline.
//
// Unsigned nodes are not a violation here: a Void or empty-vector placeholder
// is exactly what a node looks like before it is signed. Use
// RequireFullySigned to insist every node is signed.
//
// Source-account entries carry no credentials to check, but their invocation
// trees are still converted by the host, so the value rules apply to them.
func ValidateEntry(entry xdr.SorobanAuthorizationEntry) error {
	if err := validateEntryCredentials(entry); err != nil {
		return fmt.Errorf("soroauth: validate entry: %w", err)
	}
	if err := validateInvocationRules(entry.RootInvocation, "root_invocation", 1); err != nil {
		return fmt.Errorf("soroauth: validate entry: %w", err)
	}
	return nil
}

func validateEntryCredentials(entry xdr.SorobanAuthorizationEntry) error {
	switch entry.Credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		return nil
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
	default:
		return ErrUnsupportedCredentials
	}

	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		return err
	}
	const topPath = "credentials"
	if err := validateCredentialAddress(credentials.Address, topPath); err != nil {
		return err
	}
	// The top-level signature is converted with nothing else on the host's
	// depth budget (auth.rs:2437-2457).
	if err := validateSignatureValue(credentials.Address, credentials.Signature, topPath, 0); err != nil {
		return err
	}

	if entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
		return nil
	}
	if err := validateDelegateTree(entry.Credentials.AddressWithDelegates.Delegates, topPath, 1); err != nil {
		return err
	}
	// Ordering and uniqueness reuse ValidateDelegateOrder, which reports them
	// as RuleDelegateOrder and RuleDelegateUnique violations. The depth walk
	// above runs first so the tree it follows is already known to be within
	// MaxDelegateDepth.
	return ValidateDelegateOrder(entry)
}

// validateDelegateTree applies RuleDelegateDepth, RuleAddressType and the
// signature rules to every delegate, recursively. depth is the level of nodes,
// with the top-level delegates array at 1.
func validateDelegateTree(nodes []xdr.SorobanDelegateSignature, parentPath string, depth int) error {
	for i := range nodes {
		node := &nodes[i]
		label, err := FormatAddress(node.Address)
		if err != nil {
			label = fmt.Sprintf("#%d", i)
		}
		path := parentPath + ".delegates[" + label + "]"
		if depth > 1 {
			path = parentPath + ".nested[" + label + "]"
		}

		if err := checkDelegateDepth(depth, node.Signature, path); err != nil {
			return err
		}
		if err := validateCredentialAddress(node.Address, path); err != nil {
			return err
		}
		// The host converts a delegate's signature inside the depth level it
		// entered for that delegate: depth+1 levels are already spent, the
		// root's included.
		if err := validateSignatureValue(node.Address, node.Signature, path, depth+1); err != nil {
			return err
		}
		if err := validateDelegateTree(node.NestedDelegates, path, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// checkDelegateDepth applies RuleDelegateDepth to one delegate at depth with
// the given signature.
//
// The host reads the tree recursively, entering one level of its depth budget
// for the root call and one for each delegate (auth.rs:2163, 2197 and 2209), and
// converts each delegate's signature inside that delegate's level, which
// spends one more level per ScVal level (conversion.rs:432-441). The budget
// starts at HostDepthLimit (budget/limits.rs:41), and entering with none left
// fails (limits.rs:83-93). So a delegate at depth k is read only when
// k + 1 + hostValueDepth(signature) <= HostDepthLimit. Against
// soroban-env-host 30.0.1 that admits depth 98 with a Void signature and
// refuses 99, and admits 96 with an ed25519 signature and refuses 97.
func checkDelegateDepth(depth int, signature xdr.ScVal, path string) error {
	if depth > MaxDelegateDepth {
		return ruleError(RuleDelegateDepth, path, fmt.Sprintf(
			"%s: delegate at depth %d exceeds soroauth's MaxDelegateDepth of %d", path, depth, MaxDelegateDepth),
			ErrDelegateDepthLimit, ErrDecodeLimit)
	}
	if !hostDelegateDepthOK(depth, hostValueDepth(signature, HostDepthLimit)) {
		return ruleError(RuleDelegateDepth, path, fmt.Sprintf(
			"%s: delegate at depth %d with a signature %d levels deep needs %d levels of the host's depth budget of %d",
			path, depth, hostValueDepth(signature, HostDepthLimit),
			depth+1+hostValueDepth(signature, HostDepthLimit), HostDepthLimit),
			ErrDelegateDepthLimit)
	}
	return nil
}

// hostDelegateDepthOK is the host's depth arithmetic for one delegate, kept
// separate so the measured host boundaries can be asserted against it
// directly.
func hostDelegateDepthOK(depth, signatureDepth int) bool {
	return depth+1+signatureDepth <= HostDepthLimit
}

// validateCredentialAddress applies RuleAddressType to a credential or
// delegate address: the host authenticates only accounts and contracts
// (auth.rs:2769-2774 for the top level, 1098-1104 for a delegate).
func validateCredentialAddress(address xdr.ScAddress, path string) error {
	switch address.Type {
	case xdr.ScAddressTypeScAddressTypeAccount, xdr.ScAddressTypeScAddressTypeContract:
		return nil
	default:
		return ruleError(RuleAddressType, path, fmt.Sprintf(
			"%s: credential address type %s is not an account or contract", path, address.Type))
	}
}

// validateSignatureValue applies the value rules to one node's signature, and
// RuleAccountSignature when the node is a classic account that has been
// signed. spent is how many levels of the host's depth budget are already used
// when the host converts this value.
func validateSignatureValue(address xdr.ScAddress, signature xdr.ScVal, path string, spent int) error {
	valuePath := path + ".signature"
	if err := validateValueRules(signature, valuePath, spent); err != nil {
		return err
	}
	if address.Type == xdr.ScAddressTypeScAddressTypeAccount && isSigned(signature) {
		return validateAccountSignature(signature, valuePath)
	}
	return nil
}

// validateAccountSignature applies RuleAccountSignature: the host converts a
// classic account's signature into a vector of AccountEd25519Signature
// structs, refuses more than MAX_ACCOUNT_SIGNATURES (20) of them, and walks
// them requiring each public key to compare strictly greater than the last
// (account_contract.rs:181-213). The struct is a contracttype with exactly the
// two fields public_key (32 bytes) and signature (64 bytes)
// (account_contract.rs:64-67).
//
// An empty vector is "no account signatures found" on chain, but here it is
// an unsigned placeholder and is never passed in; RequireFullySigned is what
// refuses it.
func validateAccountSignature(signature xdr.ScVal, path string) error {
	if signature.Type != xdr.ScValTypeScvVec || signature.Vec == nil || *signature.Vec == nil {
		return ruleError(RuleAccountSignature, path, fmt.Sprintf(
			"%s: a classic account's signature is %s, not the account signature vector", path, signature.Type))
	}
	elements := **signature.Vec
	if len(elements) > maxAccountSignatures {
		return ruleError(RuleAccountSignature, path, fmt.Sprintf(
			"%s: %d account signatures, the host accepts at most %d", path, len(elements), maxAccountSignatures),
			ErrTooManySignatures)
	}

	keys := make([][]byte, 0, len(elements))
	for i, element := range elements {
		if element.Type == xdr.ScValTypeScvMap && element.Map != nil && *element.Map != nil && len(**element.Map) != 2 {
			return ruleError(RuleAccountSignature, path, fmt.Sprintf(
				"%s[%d]: an account signature map has %d entries, want exactly public_key and signature",
				path, i, len(**element.Map)))
		}
		publicKey, _, err := parseAccountSignatureElement(element)
		if err != nil {
			return ruleError(RuleAccountSignature, path, fmt.Sprintf("%s[%d]: %v", path, i, err))
		}
		keys = append(keys, publicKey)
	}
	if i, err := checkStrictlyAscendingKeys(keys); err != nil {
		return ruleError(RuleAccountSignature, path, fmt.Sprintf("%s[%d]: %v", path, i, err))
	}
	return nil
}

// validateValueRules applies RuleValueDepth, then RuleValueForm,
// RuleSymbolForm, RuleAddressType and RuleMapKeyOrder at every level of v.
// spent is the depth budget already used when the host converts v.
func validateValueRules(v xdr.ScVal, path string, spent int) error {
	if depth := hostValueDepth(v, HostDepthLimit-spent); spent+depth > HostDepthLimit {
		return ruleError(RuleValueDepth, path, fmt.Sprintf(
			"%s: value nesting of at least %d levels, with %d already spent, exceeds the host's depth budget of %d",
			path, depth, spent, HostDepthLimit))
	}
	return walkValue(v, path, 1)
}

func walkValue(v xdr.ScVal, path string, depth int) error {
	// validateValueRules has already bounded the nesting by the host's
	// budget; this guard only keeps the walk itself from following a value
	// built in memory past it.
	if depth > HostDepthLimit {
		return ruleError(RuleValueDepth, path, fmt.Sprintf(
			"%s: value nesting exceeds the host's depth budget of %d", path, HostDepthLimit))
	}

	switch v.Type {
	case xdr.ScValTypeScvContractInstance, xdr.ScValTypeScvLedgerKeyContractInstance, xdr.ScValTypeScvLedgerKeyNonce:
		return ruleError(RuleValueForm, path, fmt.Sprintf(
			"%s: %s values cannot be represented as host values", path, v.Type))
	case xdr.ScValTypeScvSymbol:
		if v.Sym == nil {
			return ruleError(RuleValueForm, path, fmt.Sprintf("%s: symbol value has no body", path))
		}
		return validateSymbol(string(*v.Sym), path)
	case xdr.ScValTypeScvAddress:
		if v.Address == nil {
			return ruleError(RuleValueForm, path, fmt.Sprintf("%s: address value has no body", path))
		}
		switch v.Address.Type {
		case xdr.ScAddressTypeScAddressTypeAccount, xdr.ScAddressTypeScAddressTypeContract,
			xdr.ScAddressTypeScAddressTypeMuxedAccount:
			return nil
		default:
			return ruleError(RuleAddressType, path, fmt.Sprintf(
				"%s: address type %s is not accepted in a host value", path, v.Address.Type))
		}
	case xdr.ScValTypeScvVec:
		if v.Vec == nil || *v.Vec == nil {
			return ruleError(RuleValueForm, path, fmt.Sprintf("%s: vec has no body", path))
		}
		for i, element := range **v.Vec {
			if err := walkValue(element, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
				return err
			}
		}
	case xdr.ScValTypeScvMap:
		if v.Map == nil || *v.Map == nil {
			return ruleError(RuleValueForm, path, fmt.Sprintf("%s: map has no body", path))
		}
		entries := **v.Map
		for i, entry := range entries {
			if err := walkValue(entry.Key, fmt.Sprintf("%s{%d}.key", path, i), depth+1); err != nil {
				return err
			}
			if err := walkValue(entry.Val, fmt.Sprintf("%s{%d}.val", path, i), depth+1); err != nil {
				return err
			}
			if i == 0 {
				continue
			}
			order, err := compareScVal(entries[i-1].Key, entry.Key, depth+1)
			if err != nil {
				return ruleError(RuleMapKeyOrder, path, fmt.Sprintf("%s{%d}: %v", path, i, err))
			}
			if order == 0 {
				return ruleError(RuleMapKeyOrder, path, fmt.Sprintf(
					"%s{%d}: map key repeats the previous key", path, i))
			}
			if order > 0 {
				return ruleError(RuleMapKeyOrder, path, fmt.Sprintf(
					"%s{%d}: map keys are not in ascending host order", path, i))
			}
		}
	}
	return nil
}

// maxSymbolBytes is SCSYMBOL_LIMIT, the host's symbol length limit
// (host_object.rs:296-303).
const maxSymbolBytes = 32

// validateSymbol applies RuleSymbolForm: at most 32 bytes, each one of
// [_0-9A-Za-z] (host_object.rs:294-314, symbol.rs:237-246).
func validateSymbol(symbol, path string) error {
	if len(symbol) > maxSymbolBytes {
		return ruleError(RuleSymbolForm, path, fmt.Sprintf(
			"%s: symbol is %d bytes, the host accepts at most %d", path, len(symbol), maxSymbolBytes))
	}
	for i := 0; i < len(symbol); i++ {
		b := symbol[i]
		if b == '_' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
			continue
		}
		return ruleError(RuleSymbolForm, path, fmt.Sprintf(
			"%s: symbol byte 0x%02x at offset %d is not in [A-Za-z0-9_]", path, b, i))
	}
	return nil
}

// validateInvocationRules applies the value, symbol and create-contract rules
// to an invocation and its sub-invocations. Every argument is converted with
// nothing else on the host's depth budget (auth.rs:809; constructor arguments
// at account_contract.rs:111).
func validateInvocationRules(invocation xdr.SorobanAuthorizedInvocation, path string, depth int) error {
	if err := checkTraversalDepth(depth); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	function := invocation.Function
	switch function.Type {
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn:
		if function.ContractFn == nil {
			return fmt.Errorf("%s: contract function arm is empty", path)
		}
		if err := validateSymbol(string(function.ContractFn.FunctionName), path+".function_name"); err != nil {
			return err
		}
		if err := validateArgs(function.ContractFn.Args, path+".args"); err != nil {
			return err
		}
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn:
		if function.CreateContractHostFn == nil {
			return fmt.Errorf("%s: create contract arm is empty", path)
		}
		if err := validateCreateContract(function.CreateContractHostFn.Executable,
			function.CreateContractHostFn.ContractIdPreimage, path); err != nil {
			return err
		}
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn:
		if function.CreateContractV2HostFn == nil {
			return fmt.Errorf("%s: create contract v2 arm is empty", path)
		}
		args := function.CreateContractV2HostFn
		if err := validateCreateContract(args.Executable, args.ContractIdPreimage, path); err != nil {
			return err
		}
		if err := validateArgs(args.ConstructorArgs, path+".constructor_args"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s: %w", path, ErrUnsupportedFunctionType)
	}

	for i, sub := range invocation.SubInvocations {
		if err := validateInvocationRules(sub, fmt.Sprintf("%s.sub_invocations[%d]", path, i), depth+1); err != nil {
			return err
		}
	}
	return nil
}

func validateArgs(args []xdr.ScVal, path string) error {
	for i, arg := range args {
		if err := validateValueRules(arg, fmt.Sprintf("%s[%d]", path, i), 0); err != nil {
			return err
		}
	}
	return nil
}

// validateCreateContract applies RuleCreateContractAuth. The host builds the
// authorization context for every authentication, classic accounts included
// (auth.rs:2749-2750), and refuses a create-contract call whose executable is
// the Stellar Asset contract or whose contract ID comes from an asset
// (account_contract.rs:82-104).
func validateCreateContract(executable xdr.ContractExecutable, preimage xdr.ContractIdPreimage, path string) error {
	if executable.Type == xdr.ContractExecutableTypeContractExecutableStellarAsset {
		return ruleError(RuleCreateContractAuth, path, fmt.Sprintf(
			"%s: a Stellar Asset executable is not allowed in an authorized create-contract call", path))
	}
	if preimage.Type == xdr.ContractIdPreimageTypeContractIdPreimageFromAsset {
		return ruleError(RuleCreateContractAuth, path, fmt.Sprintf(
			"%s: an asset contract ID preimage is not allowed in an authorized create-contract call", path))
	}
	return nil
}
