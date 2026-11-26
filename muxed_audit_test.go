package soroauth

import (
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

func TestMuxedAccountArgumentHandling(t *testing.T) {
	// Load the golden vector that has a muxed address in an invocation argument
	entry := loadVectorEntry(t, "v2_muxed_address_in_argument")

	contractFn := entry.RootInvocation.Function.ContractFn
	if contractFn == nil {
		t.Fatalf("expected ContractFn")
	}

	// 1. Inspect argument
	var foundMuxed bool
	var muxedStr string
	for _, arg := range contractFn.Args {
		if arg.Type == xdr.ScValTypeScvAddress && arg.Address != nil && arg.Address.Type == xdr.ScAddressTypeScAddressTypeMuxedAccount {
			foundMuxed = true
			formatted, err := FormatArgumentAddress(*arg.Address)
			if err != nil {
				t.Fatalf("FormatArgumentAddress failed on muxed account: %v", err)
			}
			muxedStr = formatted
			if !strings.HasPrefix(formatted, "M") {
				t.Errorf("expected muxed address to start with 'M', got %q", formatted)
			}
			if len(formatted) != 69 {
				t.Errorf("expected 69-character M... strkey, got len %d: %q", len(formatted), formatted)
			}

			// FormatScVal test
			scValStr := FormatScVal(arg)
			if scValStr != formatted {
				t.Errorf("FormatScVal = %q, want %q", scValStr, formatted)
			}

			// Ensure FormatAddress strictly REFUSES muxed address
			_, errCred := FormatAddress(*arg.Address)
			if errCred == nil {
				t.Errorf("FormatAddress unexpectedly succeeded on muxed address; must fail closed")
			}
		}
	}
	if !foundMuxed {
		t.Fatalf("vector did not contain an ScAddressTypeScAddressTypeMuxedAccount argument")
	}

	// 2. Diff test: compare entry with modified entry where argument changes
	entryB := entry
	entryB.RootInvocation = entry.RootInvocation
	// Modify the function name or arg to trigger diff
	u32val := xdr.Uint32(42)
	entryB.RootInvocation.Function.ContractFn = &xdr.InvokeContractArgs{
		ContractAddress: contractFn.ContractAddress,
		FunctionName:    contractFn.FunctionName,
		Args:            []xdr.ScVal{{Type: xdr.ScValTypeScvU32, U32: &u32val}},
	}

	diff, err := DiffEntries(entry, entryB)
	if err != nil {
		t.Fatalf("DiffEntries failed: %v", err)
	}
	if len(diff.Changes) == 0 {
		t.Fatalf("expected diff changes, got none")
	}

	// 3. Tree renderer test: RenderInvocationWithArgs shows full M... address
	rendered := RenderInvocationWithArgs(entry.RootInvocation)
	if !strings.Contains(rendered, muxedStr) {
		t.Errorf("RenderInvocationWithArgs output does not contain full muxed address %q:\n%s", muxedStr, rendered)
	}
}

func TestCredentialsStillRefuseMuxed(t *testing.T) {
	// Ensure ParseAddress refuses M...
	muxedAddress := "MAYTEMZUGU3DOOBZGAYTEMZUGU3DOOBZGAYTEMZUGU3DOOBZGAYTEAAAAAAAAABQHG6U6"
	_, err := ParseAddress(muxedAddress)
	if err == nil {
		t.Errorf("ParseAddress must refuse muxed addresses for credentials")
	}
	if !strings.Contains(err.Error(), "muxed (M…) address") {
		t.Errorf("expected error message to mention muxed address, got: %v", err)
	}
}
