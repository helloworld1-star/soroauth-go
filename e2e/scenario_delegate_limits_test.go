//go:build e2e

package e2e

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// hostVoidDelegateLimit is the deepest delegate the host reads when the deepest
// node's signature is Void: k + 1 + depth(Void) <= HostDepthLimit, so
// HostDepthLimit - 2. docs/host-rules.md derives it and testdata/host-probe
// measures it offline; scenarios S-host and S-over confirm it on testnet.
const hostVoidDelegateLimit = soroauth.HostDepthLimit - 2

// fillerChain returns a single-path chain of Void-signed delegate nodes, one
// per address, nested in order. The addresses are throwaway testnet accounts
// that are never funded and never sign: the modular account delegates only to
// its registered signer, so the host reads these nodes but never matches them.
func fillerChain(t *testing.T, addresses []string) []xdr.SorobanDelegateSignature {
	t.Helper()
	var nested []xdr.SorobanDelegateSignature
	for i := len(addresses) - 1; i >= 0; i-- {
		nested = []xdr.SorobanDelegateSignature{{
			Address:         scAddressOf(t, addresses[i]),
			Signature:       xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			NestedDelegates: nested,
		}}
	}
	return nested
}

// fillerAddresses generates n throwaway G addresses. They are generated at run
// time and never written anywhere, like every other e2e key.
func fillerAddresses(t *testing.T, n int) []string {
	t.Helper()
	addresses := make([]string, 0, n)
	for i := 0; i < n; i++ {
		kp, err := keypair.Random()
		if err != nil {
			t.Fatalf("generating filler address %d: %v", i, err)
		}
		addresses = append(addresses, kp.Address())
	}
	return addresses
}

// prepareDelegateChain wraps the contract account's entry with one registered
// delegate, signer, carrying `nested` as its own nested delegate chain. It is
// built with soroauth.WithDelegates, so it is held to MaxDelegateDepth.
func prepareDelegateChain(contract, signer string, nested []string) prepareFunc {
	return func(t *testing.T, entries []xdr.SorobanAuthorizationEntry, validUntil uint32) []xdr.SorobanAuthorizationEntry {
		t.Helper()

		var chain []soroauth.Delegate
		for i := len(nested) - 1; i >= 0; i-- {
			chain = []soroauth.Delegate{{Address: nested[i], Nested: chain}}
		}
		tree := []soroauth.Delegate{{Address: signer, Nested: chain}}

		prepared := make([]xdr.SorobanAuthorizationEntry, 0, len(entries))
		for i, entry := range entries {
			info, err := soroauth.Inspect(entry)
			if err != nil {
				t.Fatalf("inspecting recorded entry %d: %v", i, err)
			}
			if info.CredentialType == soroauth.CredentialTypeSourceAccount || info.Address != contract {
				prepared = append(prepared, entry)
				continue
			}
			wrapped, err := soroauth.WithDelegates(entry, validUntil, tree, nil)
			if err != nil {
				t.Fatalf("WithDelegates on entry %d: %v", i, err)
			}
			prepared = append(prepared, wrapped)
		}
		return prepared
	}
}

// deepenAfterSigning returns an afterSign hook that replaces the registered
// delegate's nested chain with `chain`, after soroauth has signed it.
//
// This is how the scenarios reach depths soroauth itself refuses to sign: the
// CAP-71-01 preimage (HashIdPreimageSorobanAuthorizationWithAddress: network
// ID, nonce, expiration, address and invocation) does not include the delegate
// tree, so deepening it leaves the delegate's signature valid. The hook first
// asserts that soroauth would have refused the deepened entry before signing.
func deepenAfterSigning(contract string, chain []xdr.SorobanDelegateSignature, depth int) func(*testing.T, []xdr.SorobanAuthorizationEntry) []xdr.SorobanAuthorizationEntry {
	return func(t *testing.T, entries []xdr.SorobanAuthorizationEntry) []xdr.SorobanAuthorizationEntry {
		t.Helper()
		deepened := 0
		for i := range entries {
			entry := &entries[i]
			if entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
				continue
			}
			address, err := soroauth.FormatAddress(entry.Credentials.AddressWithDelegates.AddressCredentials.Address)
			if err != nil || address != contract {
				continue
			}
			delegates := entry.Credentials.AddressWithDelegates.Delegates
			if len(delegates) != 1 {
				t.Fatalf("expected the one registered delegate, found %d", len(delegates))
			}
			delegates[0].NestedDelegates = chain
			deepened++

			err = soroauth.ValidateEntry(*entry)
			if !errors.Is(err, soroauth.ErrDelegateDepthLimit) {
				t.Fatalf("soroauth.ValidateEntry on the depth-%d tree returned %v; it must refuse it with "+
					"ErrDelegateDepthLimit, or the library would sign trees past its own limit", depth, err)
			}
			t.Logf("soroauth refuses the depth-%d tree before signing, as it must: %v", depth, truncate(err.Error(), 200))
		}
		if deepened != 1 {
			t.Fatalf("deepened %d entries, want exactly the contract's one", deepened)
		}
		return entries
	}
}

// TestScenarioDelegateDepthBoundary confirms the delegate depth limit on
// testnet at both boundaries (#622):
//
//   - S: a tree of exactly MaxDelegateDepth, built by WithDelegates and signed
//     by AuthorizeAll, is accepted — soroauth's limit is inside the host's.
//   - S-host: the same tree deepened after signing to the host's limit for a
//     Void-signed deepest node (98) is accepted.
//   - S-over: one level deeper (99) is refused by the host after the fee, with
//     Error(Context, ExceededLimit).
//
// The account is the modular-account fixture with one registered signer, D1.
// Its __check_auth delegates only to D1, so the filler chain nested under D1 is
// read by the host — which is where the depth limit applies — but never
// authenticated.
func TestScenarioDelegateDepthBoundary(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	d1 := h.newAccount(t, "delegate D1")
	to := h.newAccount(t, "recipient B")

	deployed := h.deployModularAccount(t, payer, []string{d1.Address()})
	h.fundContract(t, payer, deployed.ContractAddress, transferAmount*10)

	// The chain under D1 provides depths 2..n; D1 itself is depth 1.
	filler := fillerAddresses(t, hostVoidDelegateLimit)
	signers := []soroauth.Signer{soroauth.NewEd25519Signer(d1)}
	newOp := func() txnbuild.InvokeHostFunction {
		return h.transferOp(t, scAddressOf(t, deployed.ContractAddress), scAddressOf(t, to.Address()),
			transferAmount, payer.Address())
	}
	notes := []string{
		"modular-account contract: " + deployed.ContractAddress,
		"contract deploy tx: " + deployed.CreateTxHash,
		"Registered signer (depth 1, ed25519-signed by soroauth): " + d1.Address(),
		"Nested under it: a chain of Void-signed throwaway accounts that the account never delegates to.",
		fmt.Sprintf("Host depth rule: a delegate at depth k with signature s needs k + 1 + depth(s) <= %d (docs/host-rules.md).",
			soroauth.HostDepthLimit),
	}

	t.Run("S library limit accepted", func(t *testing.T) {
		result := runScenario(t, h, scenarioSpec{
			payer:        payer,
			op:           newOp(),
			upgradedAuth: true,
			signers:      signers,
			prepare:      prepareDelegateChain(deployed.ContractAddress, d1.Address(), filler[:soroauth.MaxDelegateDepth-1]),
		})
		logSubmission(t, result)
		record(scenarioResult{
			ID:        "S",
			Name:      "a delegate tree of exactly MaxDelegateDepth is accepted live",
			Proves:    fmt.Sprintf("A delegates entry %d levels deep, built with WithDelegates and signed with AuthorizeAll, is accepted by the host: soroauth's MaxDelegateDepth is inside the host's depth limit.", soroauth.MaxDelegateDepth),
			TxHash:    result.Hash,
			Ledger:    result.Ledger,
			Arm:       result.Arm,
			Succeeded: result.Status == rpc.TransactionStatusSuccess,
			RawError:  result.RawError,
			Notes:     append(append([]string{}, notes...), fmt.Sprintf("Tree depth: %d (MaxDelegateDepth).", soroauth.MaxDelegateDepth)),
		})
		if result.Status != rpc.TransactionStatusSuccess {
			t.Fatalf("a tree of MaxDelegateDepth failed on-chain (status %s):\n%s", result.Status, result.RawError)
		}
		requireDelegatesArm(t, result)
	})

	t.Run("S-host host limit accepted", func(t *testing.T) {
		chain := fillerChain(t, filler[:hostVoidDelegateLimit-1])
		result := runScenario(t, h, scenarioSpec{
			payer:        payer,
			op:           newOp(),
			upgradedAuth: true,
			signers:      signers,
			prepare:      prepareDelegateChain(deployed.ContractAddress, d1.Address(), nil),
			afterSign:    deepenAfterSigning(deployed.ContractAddress, chain, hostVoidDelegateLimit),
		})
		logSubmission(t, result)
		record(scenarioResult{
			ID:        "S-host",
			Name:      "a delegate tree at the host's depth limit is accepted live",
			Proves:    fmt.Sprintf("A delegates entry %d levels deep with a Void-signed deepest node — the host's limit — is accepted. soroauth refuses to sign it, so it was deepened after signing; the delegate tree is not part of the CAP-71-01 preimage.", hostVoidDelegateLimit),
			TxHash:    result.Hash,
			Ledger:    result.Ledger,
			Arm:       result.Arm,
			Succeeded: result.Status == rpc.TransactionStatusSuccess,
			RawError:  result.RawError,
			Notes:     append(append([]string{}, notes...), fmt.Sprintf("Tree depth: %d (HostDepthLimit - 2).", hostVoidDelegateLimit)),
		})
		if result.Status != rpc.TransactionStatusSuccess {
			t.Fatalf("a tree at the host's limit failed on-chain (status %s):\n%s", result.Status, result.RawError)
		}
		requireDelegatesArm(t, result)
	})

	t.Run("S-over one past the host limit refused", func(t *testing.T) {
		over := append(append([]string{}, filler...), fillerAddresses(t, 1)...)
		chain := fillerChain(t, over[:hostVoidDelegateLimit])
		result := runScenario(t, h, scenarioSpec{
			payer:         payer,
			op:            newOp(),
			upgradedAuth:  true,
			expectFailure: true,
			signers:       signers,
			prepare:       prepareDelegateChain(deployed.ContractAddress, d1.Address(), nil),
			afterSign:     deepenAfterSigning(deployed.ContractAddress, chain, hostVoidDelegateLimit+1),
		})
		logSubmission(t, result)
		t.Logf("RAW ERROR:\n%s", result.RawError)

		exceeded := hostReportedExceededLimit(t, result.Diagnostics)
		record(scenarioResult{
			ID:              "S-over",
			Name:            "a delegate tree one past the host's depth limit is refused",
			Proves:          fmt.Sprintf("A delegates entry %d levels deep is refused by the host after the fee, with Error(Context, ExceededLimit), while reading the tree.", hostVoidDelegateLimit+1),
			TxHash:          result.Hash,
			Ledger:          result.Ledger,
			Arm:             result.Arm,
			Succeeded:       result.Status != rpc.TransactionStatusSuccess,
			ExpectRejection: true,
			RawError:        result.RawError,
			Notes: append(append([]string{}, notes...),
				fmt.Sprintf("Tree depth: %d (HostDepthLimit - 1).", hostVoidDelegateLimit+1),
				fmt.Sprintf("Error(Context, ExceededLimit) in the host diagnostics: %v.", exceeded)),
		})
		if result.Status == rpc.TransactionStatusSuccess {
			t.Fatal("the host accepted a tree one past its depth limit; S-over proves nothing if this succeeds")
		}
		if !exceeded {
			t.Errorf("the transaction failed, but the host did not report Error(Context, ExceededLimit); " +
				"it may have failed for a reason unrelated to the depth limit")
		}
	})
}

func logSubmission(t *testing.T, result submission) {
	t.Helper()
	t.Logf("tx hash: %s", result.Hash)
	t.Logf("ledger:  %d", result.Ledger)
	t.Logf("status:  %s", result.Status)
	t.Logf("arm:     %s", result.Arm)
	t.Logf("link:    %s%s", runExplorerBase, result.Hash)
}

func requireDelegatesArm(t *testing.T, result submission) {
	t.Helper()
	if result.Arm != "SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates" {
		t.Errorf("submitted envelope carried arm %q, want the delegates arm", result.Arm)
	}
}

// hostReportedExceededLimit reports whether the host's diagnostics carry an
// Error(Context, ExceededLimit), the error its depth limiter raises
// (soroban-env-host/src/budget/limits.rs:83-93).
func hostReportedExceededLimit(t *testing.T, diagnostics []string) bool {
	t.Helper()
	for _, detail := range hostErrorDetails(t, diagnostics) {
		if detail.ErrorType == int32(xdr.ScErrorTypeSceContext) && detail.HasErrorCode &&
			detail.ErrorCode == int32(xdr.ScErrorCodeScecExceededLimit) {
			return true
		}
	}
	return false
}
