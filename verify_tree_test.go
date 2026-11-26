package soroauth

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/rpcflow/rpcfixture"
)

func TestVerifyInvocationTree_OfflineFixture(t *testing.T) {
	fixturePath := filepath.Join("rpcflow", "rpcfixture", "testdata", "simulate_record_testnet.json")
	fixture, err := rpcfixture.LoadFile(fixturePath)
	if err != nil {
		t.Fatalf("loading fixture: %v", err)
	}

	// Extract the simulation response results auth entry from Result json.RawMessage
	var resp struct {
		Results []struct {
			Auth []string `json:"auth"`
		} `json:"results"`
	}
	if err := json.Unmarshal(fixture.Exchanges[0].Result, &resp); err != nil {
		t.Fatalf("unmarshaling simulation result: %v", err)
	}

	if len(resp.Results) == 0 || len(resp.Results[0].Auth) == 0 {
		t.Fatalf("no auth entries in fixture")
	}

	var simulatedEntry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(resp.Results[0].Auth[0], &simulatedEntry); err != nil {
		t.Fatalf("unmarshaling simulated entry: %v", err)
	}

	// Check identical trees match
	libTree := simulatedEntry.RootInvocation
	hostTree := simulatedEntry.RootInvocation

	if err := VerifyInvocationTree(libTree, hostTree); err != nil {
		t.Fatalf("identical tree failed verification: %v", err)
	}
}

func TestVerifyInvocationTree_MultiLevelNesting(t *testing.T) {
	var cid xdr.ContractId
	copy(cid[:], []byte("01234567890123456789012345678901"))
	contractAddr := xdr.ScAddress{
		Type:       xdr.ScAddressTypeScAddressTypeContract,
		ContractId: &cid,
	}

	makeInvocation := func(fnName string, subs ...xdr.SorobanAuthorizedInvocation) xdr.SorobanAuthorizedInvocation {
		return xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: contractAddr,
					FunctionName:    xdr.ScSymbol(fnName),
					Args:            []xdr.ScVal{{Type: xdr.ScValTypeScvVoid}},
				},
			},
			SubInvocations: subs,
		}
	}

	// Build a 4-level deep tree (> 2 levels)
	// Level 0: root
	// Level 1: sub[0]
	// Level 2: sub[0].sub[0]
	// Level 3: sub[0].sub[0].sub[0]
	level3 := makeInvocation("depth3")
	level2 := makeInvocation("depth2", level3)
	level1 := makeInvocation("depth1", level2)
	root := makeInvocation("root", level1)

	// Test exact match
	if err := VerifyInvocationTree(root, root); err != nil {
		t.Fatalf("expected 4-level nested tree to verify cleanly: %v", err)
	}

	// Divergence at level 3 (more than 2 levels deep)
	level3Diff := makeInvocation("depth3_diverged")
	level2Diff := makeInvocation("depth2", level3Diff)
	level1Diff := makeInvocation("depth1", level2Diff)
	rootDiff := makeInvocation("root", level1Diff)

	err := VerifyInvocationTree(root, rootDiff)
	if err == nil {
		t.Fatalf("expected divergence error, got nil")
	}

	var divErr *ErrTreeDivergence
	if !errors.As(err, &divErr) {
		t.Fatalf("expected ErrTreeDivergence, got %T (%v)", err, err)
	}

	expectedPath := "root.sub[0].sub[0].sub[0].function_name"
	if divErr.Path != expectedPath {
		t.Errorf("expected path %q, got %q", expectedPath, divErr.Path)
	}
}

func TestVerifyInvocationTree_DivergenceCases(t *testing.T) {
	var cid xdr.ContractId
	copy(cid[:], []byte("11111111111111111111111111111111"))
	contractAddr := xdr.ScAddress{
		Type:       xdr.ScAddressTypeScAddressTypeContract,
		ContractId: &cid,
	}

	treeA := xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: contractAddr,
				FunctionName:    xdr.ScSymbol("transfer"),
				Args:            []xdr.ScVal{{Type: xdr.ScValTypeScvU32, U32: func() *xdr.Uint32 { v := xdr.Uint32(50); return &v }()}},
			},
		},
	}

	// Arg mismatch
	treeB := xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: contractAddr,
				FunctionName:    xdr.ScSymbol("transfer"),
				Args:            []xdr.ScVal{{Type: xdr.ScValTypeScvU32, U32: func() *xdr.Uint32 { v := xdr.Uint32(99); return &v }()}},
			},
		},
	}

	err := VerifyInvocationTree(treeA, treeB)
	if err == nil {
		t.Fatalf("expected error on arg mismatch")
	}
	var divErr *ErrTreeDivergence
	if !errors.As(err, &divErr) {
		t.Fatalf("expected ErrTreeDivergence, got %v", err)
	}
	if divErr.Path != "root.args[0]" {
		t.Errorf("expected path 'root.args[0]', got %q", divErr.Path)
	}

	// Sub-invocations count mismatch
	treeC := treeA
	treeC.SubInvocations = []xdr.SorobanAuthorizedInvocation{treeA}
	errSub := VerifyInvocationTree(treeA, treeC)
	if errSub == nil {
		t.Fatalf("expected error on sub-invocation count mismatch")
	}
	if !strings.Contains(errSub.Error(), "root.sub") {
		t.Errorf("expected error path containing 'root.sub', got %v", errSub)
	}
}
