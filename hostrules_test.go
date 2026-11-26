package soroauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// delegatesEntryWith returns a delegates-arm entry for the standard test
// account and invocation, carrying the given delegate tree as is (no sorting).
func delegatesEntryWith(t *testing.T, delegates []xdr.SorobanDelegateSignature) xdr.SorobanAuthorizationEntry {
	t.Helper()
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 42)
	entry.Credentials.AddressWithDelegates.Delegates = delegates
	return entry
}

// delegateChain builds a single-path delegate tree depth levels deep. Every
// level is a distinct deterministic test account; signature supplies each
// level's signature value.
func delegateChain(t *testing.T, depth int, signature func(level int) xdr.ScVal) []xdr.SorobanDelegateSignature {
	t.Helper()
	var nested []xdr.SorobanDelegateSignature
	for level := depth; level >= 1; level-- {
		nested = []xdr.SorobanDelegateSignature{{
			Address:         mustParse(t, testKeypair(t, fmt.Sprintf("soroauth-rule-chain-%d", level)).Address()),
			Signature:       signature(level),
			NestedDelegates: nested,
		}}
	}
	return nested
}

func voidSignature(int) xdr.ScVal { return voidVal() }

// accountSigWithKeys builds a classic account signature vector whose maps
// carry the given public keys in the given order.
func accountSigWithKeys(keys ...[]byte) xdr.ScVal {
	elements := make([]xdr.ScVal, 0, len(keys))
	for _, key := range keys {
		elements = append(elements, accountSignature(key, make([]byte, 64)))
	}
	return scVec(elements...)
}

func keyOf(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// withArgs replaces the standard test invocation's arguments.
func withArgs(t *testing.T, args ...xdr.ScVal) xdr.SorobanAuthorizationEntry {
	t.Helper()
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	entry.RootInvocation.Function.ContractFn.Args = args
	return entry
}

// withTopSignature replaces the standard V2 entry's top-level signature.
func withTopSignature(t *testing.T, signature xdr.ScVal) xdr.SorobanAuthorizationEntry {
	t.Helper()
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	entry.Credentials.AddressV2.Signature = signature
	return entry
}

// createContractEntry returns a V2 entry authorizing a create-contract call.
func createContractEntry(t *testing.T, executable xdr.ContractExecutable, preimage xdr.ContractIdPreimage) xdr.SorobanAuthorizationEntry {
	t.Helper()
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	entry.RootInvocation.Function = xdr.SorobanAuthorizedFunction{
		Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn,
		CreateContractHostFn: &xdr.CreateContractArgs{
			ContractIdPreimage: preimage,
			Executable:         executable,
		},
	}
	return entry
}

type ruleViolationCase struct {
	name  string
	rule  string
	entry func(t *testing.T) xdr.SorobanAuthorizationEntry
	// also lists further sentinels the error must match besides
	// ErrHostRuleViolation.
	also []error
	// notAlso lists sentinels the error must not match.
	notAlso []error
}

func ruleViolationCases() []ruleViolationCase {
	return []ruleViolationCase{
		{
			name: "delegates out of order",
			rule: RuleDelegateOrder,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				a := mustParse(t, testKeypair(t, "soroauth-rule-a").Address())
				b := mustParse(t, testKeypair(t, "soroauth-rule-b").Address())
				if compareBytes(t, a, b) < 0 {
					a, b = b, a
				}
				return delegatesEntryWith(t, []xdr.SorobanDelegateSignature{
					{Address: a, Signature: voidVal()}, {Address: b, Signature: voidVal()},
				})
			},
		},
		{
			name: "duplicate delegate in one array",
			rule: RuleDelegateUnique,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				a := mustParse(t, testKeypair(t, "soroauth-rule-a").Address())
				return delegatesEntryWith(t, []xdr.SorobanDelegateSignature{
					{Address: a, Signature: voidVal()}, {Address: a, Signature: voidVal()},
				})
			},
			also: []error{ErrDuplicateDelegate},
		},
		{
			name: "delegate tree deeper than MaxDelegateDepth",
			rule: RuleDelegateDepth,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				return delegatesEntryWith(t, delegateChain(t, MaxDelegateDepth+1, voidSignature))
			},
			also: []error{ErrDelegateDepthLimit, ErrDecodeLimit},
		},
		{
			name: "delegate signature that overruns the host depth budget",
			rule: RuleDelegateDepth,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				// Depth 1 plus the root call leaves 98 levels for the
				// signature; 99 is one too many.
				return delegatesEntryWith(t, delegateChain(t, 1, func(int) xdr.ScVal {
					return nestedVec(HostDepthLimit - 1)
				}))
			},
			also:    []error{ErrDelegateDepthLimit},
			notAlso: []error{ErrDecodeLimit},
		},
		{
			name:  "argument nested past the host depth budget",
			rule:  RuleValueDepth,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry { return withArgs(t, nestedVec(HostDepthLimit+1)) },
		},
		{
			name: "top-level signature nested past the host depth budget",
			rule: RuleValueDepth,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				entry := delegatesEntryWith(t, nil)
				entry.Credentials.AddressWithDelegates.AddressCredentials.Address =
					mustParse(t, testContractAddress(t, "soroauth-rule-contract-account"))
				entry.Credentials.AddressWithDelegates.AddressCredentials.Signature = nestedVec(HostDepthLimit + 1)
				return entry
			},
		},
		{
			name: "map keys out of order",
			rule: RuleMapKeyOrder,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				return withArgs(t, mapVal(
					xdr.ScMapEntry{Key: scSymbol("signature"), Val: voidVal()},
					xdr.ScMapEntry{Key: scSymbol("public_key"), Val: voidVal()}))
			},
		},
		{
			name: "map key repeated",
			rule: RuleMapKeyOrder,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				return withArgs(t, mapVal(
					xdr.ScMapEntry{Key: u32Val(1), Val: voidVal()},
					xdr.ScMapEntry{Key: u32Val(1), Val: voidVal()}))
			},
		},
		{
			name: "map keys in XDR byte order but not host order",
			rule: RuleMapKeyOrder,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				// XDR's length prefix puts {2} before {1,0}; the host's
				// lexicographic order puts {1,0} first.
				return withArgs(t, mapVal(
					xdr.ScMapEntry{Key: bytesVal(2), Val: voidVal()},
					xdr.ScMapEntry{Key: bytesVal(1, 0), Val: voidVal()}))
			},
		},
		{
			name: "vec with no body",
			rule: RuleValueForm,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				var missing *xdr.ScVec
				return withArgs(t, xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &missing})
			},
		},
		{
			name: "ledger key nonce as an argument",
			rule: RuleValueForm,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				return withArgs(t, xdr.ScVal{Type: xdr.ScValTypeScvLedgerKeyNonce, NonceKey: &xdr.ScNonceKey{Nonce: 7}})
			},
		},
		{
			name: "symbol with a byte outside the host alphabet",
			rule: RuleSymbolForm,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				return withArgs(t, scSymbol("not-a-symbol"))
			},
		},
		{
			name: "function name with a byte outside the host alphabet",
			rule: RuleSymbolForm,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				entry := withArgs(t)
				entry.RootInvocation.Function.ContractFn.FunctionName = "trans.fer"
				return entry
			},
		},
		{
			name: "muxed account as the credential address",
			rule: RuleAddressType,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				entry := withArgs(t)
				raw := xdr.Uint256(*mustParse(t, testKeypair(t, "soroauth-rule-muxed").Address()).AccountId.Ed25519)
				entry.Credentials.AddressV2.Address = xdr.ScAddress{
					Type:         xdr.ScAddressTypeScAddressTypeMuxedAccount,
					MuxedAccount: &xdr.MuxedEd25519Account{Id: 7, Ed25519: raw},
				}
				return entry
			},
		},
		{
			name: "liquidity pool address as an argument",
			rule: RuleAddressType,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				pool := xdr.PoolId{}
				address := xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeLiquidityPool, LiquidityPoolId: &pool}
				return withArgs(t, xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &address})
			},
		},
		{
			name: "classic account signature with unsorted keys",
			rule: RuleAccountSignature,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				return withTopSignature(t, accountSigWithKeys(keyOf(2), keyOf(1)))
			},
		},
		{
			name: "classic account signature with a repeated key",
			rule: RuleAccountSignature,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				return withTopSignature(t, accountSigWithKeys(keyOf(1), keyOf(1)))
			},
		},
		{
			name: "classic account signature with 21 entries",
			rule: RuleAccountSignature,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				keys := make([][]byte, 0, maxAccountSignatures+1)
				for i := 0; i <= maxAccountSignatures; i++ {
					keys = append(keys, keyOf(byte(i+1)))
				}
				return withTopSignature(t, accountSigWithKeys(keys...))
			},
			also: []error{ErrTooManySignatures},
		},
		{
			name: "classic account signature that is not the account vector",
			rule: RuleAccountSignature,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				return withTopSignature(t, bytesVal(0xAA))
			},
		},
		{
			name: "classic account signature map with an extra field",
			rule: RuleAccountSignature,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				return withTopSignature(t, scVec(mapVal(
					xdr.ScMapEntry{Key: scSymbol("extra"), Val: voidVal()},
					xdr.ScMapEntry{Key: scSymbol("public_key"), Val: bytesVal(keyOf(1)...)},
					xdr.ScMapEntry{Key: scSymbol("signature"), Val: bytesVal(make([]byte, 64)...)},
				)))
			},
		},
		{
			name: "delegate account signature with unsorted keys",
			rule: RuleAccountSignature,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				return delegatesEntryWith(t, delegateChain(t, 1, func(int) xdr.ScVal {
					return accountSigWithKeys(keyOf(9), keyOf(3))
				}))
			},
		},
		{
			name: "create-contract with the Stellar Asset executable",
			rule: RuleCreateContractAuth,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				deployer := mustParse(t, testKeypair(t, "soroauth-rule-deployer").Address())
				return createContractEntry(t,
					xdr.ContractExecutable{Type: xdr.ContractExecutableTypeContractExecutableStellarAsset},
					xdr.ContractIdPreimage{
						Type:        xdr.ContractIdPreimageTypeContractIdPreimageFromAddress,
						FromAddress: &xdr.ContractIdPreimageFromAddress{Address: deployer},
					})
			},
		},
		{
			name: "create-contract with an asset contract ID",
			rule: RuleCreateContractAuth,
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				hash := xdr.Hash{1}
				native := xdr.MustNewNativeAsset()
				return createContractEntry(t,
					xdr.ContractExecutable{Type: xdr.ContractExecutableTypeContractExecutableWasm, WasmHash: &hash},
					xdr.ContractIdPreimage{Type: xdr.ContractIdPreimageTypeContractIdPreimageFromAsset, FromAsset: &native})
			},
		},
	}
}

// TestValidateEntryReportsEachRuleViolation produces a violation of every rule
// ValidateEntry checks and asserts it is reported as that rule.
func TestValidateEntryReportsEachRuleViolation(t *testing.T) {
	for _, tc := range ruleViolationCases() {
		t.Run(tc.name, func(t *testing.T) {
			entry := tc.entry(t)
			before, err := entry.MarshalBinary()
			if err != nil {
				t.Fatalf("encoding the fixture: %v", err)
			}

			err = ValidateEntry(entry)
			if !errors.Is(err, ErrHostRuleViolation) {
				t.Fatalf("ValidateEntry error %v does not match ErrHostRuleViolation", err)
			}
			var ruleErr *HostRuleError
			if !errors.As(err, &ruleErr) {
				t.Fatalf("ValidateEntry error %v is not a *HostRuleError", err)
			}
			if ruleErr.Rule != tc.rule {
				t.Errorf("rule = %q, want %q (error: %v)", ruleErr.Rule, tc.rule, err)
			}
			if ruleErr.Path == "" {
				t.Error("the violation carries no path")
			}
			for _, sentinel := range tc.also {
				if !errors.Is(err, sentinel) {
					t.Errorf("error %v does not also match %v", err, sentinel)
				}
			}
			for _, sentinel := range tc.notAlso {
				if errors.Is(err, sentinel) {
					t.Errorf("error %v unexpectedly matches %v", err, sentinel)
				}
			}

			after, _ := entry.MarshalBinary()
			if !bytes.Equal(before, after) {
				t.Error("ValidateEntry modified its input")
			}
		})
	}
}

// TestEveryOfflineRuleHasAViolationTest is the guard on the enumeration: a
// rule added to HostRules as checked offline must come with a test that
// produces its violation, or the list claims a check nobody has seen bite.
func TestEveryOfflineRuleHasAViolationTest(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range ruleViolationCases() {
		covered[tc.rule] = true
	}
	offline := 0
	for _, rule := range HostRules() {
		if !rule.Offline {
			if rule.Why == "" {
				t.Errorf("rule %s is not checked offline but does not say why", rule.ID)
			}
			continue
		}
		offline++
		if !covered[rule.ID] {
			t.Errorf("rule %s is checked offline but no test produces its violation", rule.ID)
		}
	}
	if offline == 0 {
		t.Fatal("HostRules lists no offline rules; refusing a vacuous check")
	}
}

// TestHostRulesAreWellFormed checks the enumeration itself.
func TestHostRulesAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range HostRules() {
		if rule.ID == "" || rule.Summary == "" || rule.Source == "" {
			t.Errorf("rule %+v is missing an ID, summary or source", rule)
		}
		if !strings.Contains(rule.Source, "soroban-env-") {
			t.Errorf("rule %s cites %q, which names no rs-soroban-env crate", rule.ID, rule.Source)
		}
		if seen[rule.ID] {
			t.Errorf("rule %s is listed twice", rule.ID)
		}
		seen[rule.ID] = true
	}

	rules := HostRules()
	rules[0].ID = "changed"
	if HostRules()[0].ID == "changed" {
		t.Error("HostRules returned the package's own slice; a caller could rewrite the enumeration")
	}
}

// TestValidateEntryAcceptsEveryGoldenVector: every entry the JS reference and
// soroauth agree on byte for byte, unsigned and signed, satisfies every host
// rule. A rule that refused one of these would be refusing real entries.
func TestValidateEntryAcceptsEveryGoldenVector(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			for label, encoded := range map[string]string{"unsigned": v.UnsignedEntryXDR, "signed": v.SignedEntryXDR} {
				var entry xdr.SorobanAuthorizationEntry
				if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
					t.Fatalf("decoding the %s entry: %v", label, err)
				}
				if err := ValidateEntry(entry); err != nil {
					t.Errorf("ValidateEntry refused the %s entry: %v", label, err)
				}
			}
		})
	}
}

// TestHostDelegateDepthMatchesMeasuredBoundaries pins the host depth formula
// to the boundaries measured against soroban-env-host 30.0.1 (and 28.0.2,
// 29.0.1) with set_authorization_entries on single-path delegate chains:
//
//	void delegate sigs: max accepted delegate depth = 98; depth 99 rejected with Error(Context, ExceededLimit)
//	ed25519 delegate sigs: max accepted delegate depth = 96; depth 97 rejected with Error(Context, ExceededLimit)
//	empty-vec delegate sigs: max accepted delegate depth = 98; depth 99 rejected with Error(Context, ExceededLimit)
//
// The harness that produced those lines is testdata/host-probe.
func TestHostDelegateDepthMatchesMeasuredBoundaries(t *testing.T) {
	ed25519Sig, err := Ed25519SignatureScVal(make([]byte, 32), make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		signature xdr.ScVal
		maxDepth  int
	}{
		{"void", voidVal(), 98},
		{"empty vec", scVec(), 98},
		{"ed25519", ed25519Sig, 96},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			depth := hostValueDepth(tc.signature, HostDepthLimit)
			if !hostDelegateDepthOK(tc.maxDepth, depth) {
				t.Errorf("formula refuses depth %d, which the host accepts", tc.maxDepth)
			}
			if hostDelegateDepthOK(tc.maxDepth+1, depth) {
				t.Errorf("formula accepts depth %d, which the host refuses", tc.maxDepth+1)
			}
		})
	}
}

// TestMaxDelegateDepthIsOnePolicy asserts the relationship MaxDelegateDepth's
// doc comment claims, so the constant cannot drift from either bound it is
// derived from:
//
//   - a chain of exactly MaxDelegateDepth whose every node carries the classic
//     account signature decodes under MaxDecodeDepth, and one level deeper
//     does not — it is the decode bound, not a looser or tighter number;
//   - the host's depth formula accepts that chain, so soroauth never signs a
//     tree the host's depth rule would refuse;
//   - every soroauth path agrees on it: WithDelegates, ValidateEntry and
//     AuthorizeEntry accept MaxDelegateDepth and refuse one more.
func TestMaxDelegateDepthIsOnePolicy(t *testing.T) {
	signature, err := Ed25519SignatureScVal(make([]byte, 32), make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	signedChain := func(depth int) xdr.SorobanAuthorizationEntry {
		entry := delegatesEntryWith(t, delegateChain(t, depth, func(int) xdr.ScVal { return signature }))
		entry.Credentials.AddressWithDelegates.AddressCredentials.Signature = signature
		return entry
	}

	t.Run("decode admits exactly MaxDelegateDepth signed levels", func(t *testing.T) {
		atLimit, err := xdr.MarshalBase64(signedChain(MaxDelegateDepth))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeAuthorizationEntry(atLimit); err != nil {
			t.Errorf("a signed chain of MaxDelegateDepth (%d) does not decode: %v", MaxDelegateDepth, err)
		}
		over, err := xdr.MarshalBase64(signedChain(MaxDelegateDepth + 1))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeAuthorizationEntry(over); !errors.Is(err, ErrDecodeLimit) {
			t.Errorf("a signed chain of MaxDelegateDepth+1 decodes (err %v); MaxDelegateDepth is below "+
				"the decode bound and should be raised to it", err)
		}
	})

	t.Run("the host formula admits MaxDelegateDepth", func(t *testing.T) {
		if !hostDelegateDepthOK(MaxDelegateDepth, hostValueDepth(signature, HostDepthLimit)) {
			t.Errorf("MaxDelegateDepth %d with an ed25519 signature exceeds the host's depth budget", MaxDelegateDepth)
		}
	})

	t.Run("ValidateEntry agrees", func(t *testing.T) {
		if err := ValidateEntry(signedChain(MaxDelegateDepth)); err != nil {
			t.Errorf("ValidateEntry refused a signed chain of MaxDelegateDepth: %v", err)
		}
		if err := ValidateEntry(signedChain(MaxDelegateDepth + 1)); !errors.Is(err, ErrDelegateDepthLimit) {
			t.Errorf("ValidateEntry error for MaxDelegateDepth+1 = %v, want ErrDelegateDepthLimit", err)
		}
	})

	chainDelegates := func(depth int) []Delegate {
		var tree []Delegate
		for level := depth; level >= 1; level-- {
			tree = []Delegate{{Address: testKeypair(t, fmt.Sprintf("soroauth-rule-chain-%d", level)).Address(), Nested: tree}}
		}
		return tree
	}
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	base.Credentials.AddressV2.Signature = voidVal()

	t.Run("WithDelegates agrees", func(t *testing.T) {
		if _, err := WithDelegates(base, testValidUntilLedger, chainDelegates(MaxDelegateDepth), nil); err != nil {
			t.Errorf("WithDelegates refused MaxDelegateDepth: %v", err)
		}
		_, err := WithDelegates(base, testValidUntilLedger, chainDelegates(MaxDelegateDepth+1), nil)
		if !errors.Is(err, ErrDelegateDepthLimit) || !errors.Is(err, ErrHostRuleViolation) {
			t.Errorf("WithDelegates error for MaxDelegateDepth+1 = %v, want ErrDelegateDepthLimit", err)
		}
	})

	t.Run("AuthorizeEntry signs at MaxDelegateDepth and the result decodes", func(t *testing.T) {
		wrapped, err := WithDelegates(base, testValidUntilLedger, chainDelegates(MaxDelegateDepth), nil)
		if err != nil {
			t.Fatal(err)
		}
		leaf := testKeypair(t, fmt.Sprintf("soroauth-rule-chain-%d", MaxDelegateDepth))
		signed, err := AuthorizeEntry(context.Background(), wrapped, NewEd25519Signer(leaf),
			testValidUntilLedger, network.TestNetworkPassphrase)
		if err != nil {
			t.Fatalf("AuthorizeEntry refused the leaf of a MaxDelegateDepth chain: %v", err)
		}
		encoded, err := xdr.MarshalBase64(signed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeAuthorizationEntry(encoded); err != nil {
			t.Errorf("soroauth cannot decode the entry it signed: %v", err)
		}
	})
}

// ruleCountingSigner records whether it was asked to sign.
type ruleCountingSigner struct {
	address string
	calls   atomic.Int32
	sign    func() xdr.ScVal
}

func (s *ruleCountingSigner) Address() string { return s.address }

func (s *ruleCountingSigner) Sign(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
	s.calls.Add(1)
	return s.sign(), nil
}

// TestAuthorizeEntryRefusesBeforeSigning proves the issue's requirement that an
// over-limit or non-canonical entry is refused before any signer runs: a
// remote or hardware signer must not be asked for a signature that the host
// will throw away after fees.
func TestAuthorizeEntryRefusesBeforeSigning(t *testing.T) {
	for _, tc := range ruleViolationCases() {
		t.Run(tc.name, func(t *testing.T) {
			entry := tc.entry(t)
			if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
				t.Skip("source-account entries are passed through unsigned")
			}
			credentials, err := addressCredentials(entry.Credentials)
			if err != nil {
				t.Fatal(err)
			}
			target, err := FormatAddress(credentials.Address)
			if err != nil {
				// A muxed credential address has no G/C strkey to sign for;
				// the violation is still refused, before anything else.
				target = testKeypair(t, "soroauth-preimage-signer").Address()
			}
			signer := &ruleCountingSigner{address: target, sign: voidVal}

			got, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger,
				network.TestNetworkPassphrase, AllowResign())
			if !errors.Is(err, ErrHostRuleViolation) {
				t.Fatalf("AuthorizeEntry error = %v, want ErrHostRuleViolation", err)
			}
			if signer.calls.Load() != 0 {
				t.Errorf("the signer was called %d times for an entry that breaks %s", signer.calls.Load(), tc.rule)
			}
			if got.Credentials.Type != 0 || got.RootInvocation.Function.ContractFn != nil {
				t.Error("AuthorizeEntry returned a partial entry alongside its error")
			}
		})
	}
}

// TestAuthorizeEntryDiscardsASignatureThatBreaksARule covers the signatures
// whose own shape breaks a rule. The entry is valid until the signature is
// written, so the signer has run; the result must still be refused, and no
// entry returned.
func TestAuthorizeEntryDiscardsASignatureThatBreaksARule(t *testing.T) {
	cases := []struct {
		name  string
		rule  string
		entry func(t *testing.T) (xdr.SorobanAuthorizationEntry, string)
		sig   func() xdr.ScVal
	}{
		{
			name: "multisig vector with unsorted keys on a classic account",
			rule: RuleAccountSignature,
			entry: func(t *testing.T) (xdr.SorobanAuthorizationEntry, string) {
				entry := withArgs(t)
				address, _ := FormatAddress(entry.Credentials.AddressV2.Address)
				return entry, address
			},
			sig: func() xdr.ScVal { return accountSigWithKeys(keyOf(5), keyOf(4)) },
		},
		{
			name: "custom-account signature too deep for its delegate's depth",
			rule: RuleDelegateDepth,
			entry: func(t *testing.T) (xdr.SorobanAuthorizationEntry, string) {
				contract := testContractAddress(t, "soroauth-rule-deep-delegate")
				entry := delegatesEntryWith(t, []xdr.SorobanDelegateSignature{{
					Address: mustParse(t, contract), Signature: voidVal(),
				}})
				return entry, contract
			},
			// Delegate depth 1: 1 + 1 + 99 > 100.
			sig: func() xdr.ScVal { return nestedVec(HostDepthLimit - 1) },
		},
		{
			name: "custom-account signature with unsorted map keys",
			rule: RuleMapKeyOrder,
			entry: func(t *testing.T) (xdr.SorobanAuthorizationEntry, string) {
				contract := testContractAddress(t, "soroauth-rule-map-delegate")
				entry := delegatesEntryWith(t, []xdr.SorobanDelegateSignature{{
					Address: mustParse(t, contract), Signature: voidVal(),
				}})
				return entry, contract
			},
			sig: func() xdr.ScVal {
				return mapVal(xdr.ScMapEntry{Key: u32Val(2), Val: voidVal()}, xdr.ScMapEntry{Key: u32Val(1), Val: voidVal()})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry, target := tc.entry(t)
			if err := ValidateEntry(entry); err != nil {
				t.Fatalf("the fixture must be valid before signing: %v", err)
			}
			signer := &ruleCountingSigner{address: target, sign: tc.sig}
			got, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger,
				network.TestNetworkPassphrase)
			var ruleErr *HostRuleError
			if !errors.As(err, &ruleErr) || ruleErr.Rule != tc.rule {
				t.Fatalf("AuthorizeEntry error = %v, want a %s violation", err, tc.rule)
			}
			if signer.calls.Load() != 1 {
				t.Errorf("signer called %d times, want 1", signer.calls.Load())
			}
			if got.Credentials.Type != 0 {
				t.Error("AuthorizeEntry returned an entry alongside its error")
			}
		})
	}
}

// TestStreamingSignValidatesBeforeTheVisitor: StreamingSign uses the same
// single entry point, before the first visitor call.
func TestStreamingSignValidatesBeforeTheVisitor(t *testing.T) {
	entry := delegatesEntryWith(t, delegateChain(t, MaxDelegateDepth+1, voidSignature))
	var calls atomic.Int32
	visitor := func(context.Context, string, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
		calls.Add(1)
		return voidVal(), nil
	}
	_, err := StreamingSign(context.Background(), entry, visitor, testValidUntilLedger, network.TestNetworkPassphrase)
	if !errors.Is(err, ErrDelegateDepthLimit) {
		t.Errorf("StreamingSign error = %v, want ErrDelegateDepthLimit", err)
	}
	if calls.Load() != 0 {
		t.Errorf("the visitor was called %d times for an over-deep tree", calls.Load())
	}
}

// TestHostRuleErrorMessagesStayShort: a violation deep in a tree near
// MaxDelegateDepth has a path of several kilobytes; the message quotes its
// tail and the full path stays on the error.
func TestHostRuleErrorMessagesStayShort(t *testing.T) {
	err := ValidateEntry(delegatesEntryWith(t, delegateChain(t, MaxDelegateDepth+1, voidSignature)))
	var ruleErr *HostRuleError
	if !errors.As(err, &ruleErr) {
		t.Fatalf("error %v is not a *HostRuleError", err)
	}
	if len(ruleErr.Path) <= maxMessagePath {
		t.Fatalf("the fixture's path is only %d bytes; it does not exercise shortening", len(ruleErr.Path))
	}
	if len(err.Error()) > maxMessagePath+300 {
		t.Errorf("message is %d bytes; it should quote at most the last %d bytes of the path", len(err.Error()), maxMessagePath)
	}
	if !strings.Contains(err.Error(), "MaxDelegateDepth") {
		t.Errorf("message %q lost the violation itself", err)
	}
}

// TestNewAccountMultiSignerSharesTheOrderingCheck: the multisig signer and
// ValidateEntry use one implementation of the host's strictly ascending rule,
// so a vector the signer produces always passes ValidateEntry.
func TestNewAccountMultiSignerSharesTheOrderingCheck(t *testing.T) {
	account := testKeypair(t, "soroauth-rule-multisig-account")
	keys := []string{"soroauth-rule-multisig-3", "soroauth-rule-multisig-1", "soroauth-rule-multisig-2"}
	signer, err := NewAccountMultiSigner(account.Address(),
		testKeypair(t, keys[0]), testKeypair(t, keys[1]), testKeypair(t, keys[2]))
	if err != nil {
		t.Fatal(err)
	}
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	entry.Credentials.AddressV2.Address = mustParse(t, account.Address())
	entry.Credentials.AddressV2.Signature = scVec()
	if _, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger,
		network.TestNetworkPassphrase); err != nil {
		t.Errorf("AuthorizeEntry refused NewAccountMultiSigner's own vector: %v", err)
	}

	if _, err := NewAccountMultiSigner(account.Address(), testKeypair(t, keys[0]), testKeypair(t, keys[0])); err == nil {
		t.Error("NewAccountMultiSigner accepted a repeated key")
	}
	if i, err := checkStrictlyAscendingKeys([][]byte{keyOf(1), keyOf(3), keyOf(2)}); err == nil || i != 2 {
		t.Errorf("checkStrictlyAscendingKeys = %d, %v; want index 2 and an error", i, err)
	}
}
