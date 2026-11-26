package soroauth

import (
	"bytes"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// ErrTreeDivergence is returned when the library's invocation tree and the
// host's reported simulation tree diverge structurally.
type ErrTreeDivergence struct {
	// Path is the tree path where divergence occurred, e.g. "root.sub[0].args[1]".
	Path string
	// Reason describes how the trees diverged at that path.
	Reason string
}

// Error renders the divergence description for an ErrTreeDivergence.
func (e *ErrTreeDivergence) Error() string {
	return fmt.Sprintf("invocation tree divergence at %s: %s", e.Path, e.Reason)
}

// VerifyInvocationTree compares the library's view of an authorized invocation tree
// against the invocation tree reported by the host during simulation, and fails on
// structural divergence.
//
// The comparison checks:
// - Invocation function type (ContractFn vs CreateContractHostFn)
// - Contract function target contract address, function name, and arguments
// - Exact count, ordering, and recursive structure of all sub-invocations to arbitrary depth (> 2 levels).
//
// When trees differ, it returns an *ErrTreeDivergence containing the exact path
// where divergence occurred.
func VerifyInvocationTree(libraryTree, hostTree xdr.SorobanAuthorizedInvocation) error {
	return compareInvocations(libraryTree, hostTree, "root")
}

func compareInvocations(lib, host xdr.SorobanAuthorizedInvocation, path string) error {
	// Compare function types
	if lib.Function.Type != host.Function.Type {
		return &ErrTreeDivergence{
			Path:   fmt.Sprintf("%s.function.type", path),
			Reason: fmt.Sprintf("library has %v, host has %v", lib.Function.Type, host.Function.Type),
		}
	}

	switch lib.Function.Type {
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn:
		libFn := lib.Function.ContractFn
		hostFn := host.Function.ContractFn
		if (libFn == nil) != (hostFn == nil) {
			return &ErrTreeDivergence{
				Path:   fmt.Sprintf("%s.function.contract_fn", path),
				Reason: fmt.Sprintf("nil mismatch: library is %v, host is %v", libFn == nil, hostFn == nil),
			}
		}
		if libFn != nil && hostFn != nil {
			// Compare contract address
			libAddrBytes, err := libFn.ContractAddress.MarshalBinary()
			if err != nil {
				return fmt.Errorf("soroauth: marshaling library contract address at %s: %w", path, err)
			}
			hostAddrBytes, err := hostFn.ContractAddress.MarshalBinary()
			if err != nil {
				return fmt.Errorf("soroauth: marshaling host contract address at %s: %w", path, err)
			}
			if !bytes.Equal(libAddrBytes, hostAddrBytes) {
				return &ErrTreeDivergence{
					Path:   fmt.Sprintf("%s.contract_address", path),
					Reason: "contract addresses do not match",
				}
			}

			// Compare function name
			if string(libFn.FunctionName) != string(hostFn.FunctionName) {
				return &ErrTreeDivergence{
					Path:   fmt.Sprintf("%s.function_name", path),
					Reason: fmt.Sprintf("library calls %q, host reports %q", string(libFn.FunctionName), string(hostFn.FunctionName)),
				}
			}

			// Compare arguments count and values
			if len(libFn.Args) != len(hostFn.Args) {
				return &ErrTreeDivergence{
					Path:   fmt.Sprintf("%s.args", path),
					Reason: fmt.Sprintf("library has %d args, host reports %d", len(libFn.Args), len(hostFn.Args)),
				}
			}
			for i := range libFn.Args {
				argPath := fmt.Sprintf("%s.args[%d]", path, i)
				libBytes, err := libFn.Args[i].MarshalBinary()
				if err != nil {
					return fmt.Errorf("soroauth: marshaling library arg at %s: %w", argPath, err)
				}
				hostBytes, err := hostFn.Args[i].MarshalBinary()
				if err != nil {
					return fmt.Errorf("soroauth: marshaling host arg at %s: %w", argPath, err)
				}
				if !bytes.Equal(libBytes, hostBytes) {
					return &ErrTreeDivergence{
						Path:   argPath,
						Reason: "argument value mismatch",
					}
				}
			}
		}

	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn:
		libCreate := lib.Function.CreateContractHostFn
		hostCreate := host.Function.CreateContractHostFn
		if (libCreate == nil) != (hostCreate == nil) {
			return &ErrTreeDivergence{
				Path:   fmt.Sprintf("%s.function.create_contract", path),
				Reason: fmt.Sprintf("nil mismatch: library is %v, host is %v", libCreate == nil, hostCreate == nil),
			}
		}
		if libCreate != nil && hostCreate != nil {
			libBytes, err := libCreate.MarshalBinary()
			if err != nil {
				return fmt.Errorf("soroauth: marshaling library create_contract at %s: %w", path, err)
			}
			hostBytes, err := hostCreate.MarshalBinary()
			if err != nil {
				return fmt.Errorf("soroauth: marshaling host create_contract at %s: %w", path, err)
			}
			if !bytes.Equal(libBytes, hostBytes) {
				return &ErrTreeDivergence{
					Path:   fmt.Sprintf("%s.create_contract", path),
					Reason: "create contract parameters mismatch",
				}
			}
		}
	}

	// Compare sub-invocations length
	if len(lib.SubInvocations) != len(host.SubInvocations) {
		return &ErrTreeDivergence{
			Path:   fmt.Sprintf("%s.sub", path),
			Reason: fmt.Sprintf("sub-invocation count mismatch: library has %d, host reports %d", len(lib.SubInvocations), len(host.SubInvocations)),
		}
	}

	// Recurse into sub-invocations in exact order
	for i := range lib.SubInvocations {
		subPath := fmt.Sprintf("%s.sub[%d]", path, i)
		if err := compareInvocations(lib.SubInvocations[i], host.SubInvocations[i], subPath); err != nil {
			return err
		}
	}

	return nil
}
