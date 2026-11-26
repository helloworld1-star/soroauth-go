package soroauth

import (
	"bytes"
	"cmp"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// This file models the two properties of an ScVal that the Soroban host
// enforces when it converts the value into a host Val: how much of the host's
// depth budget the conversion spends, and the total order the host sorts map
// keys by. Both are read from rs-soroban-env 30.0.1 (the host testnet runs at
// protocol 30) and were confirmed identical in 27.0.1, 28.0.2 and 29.0.1; see
// docs/host-rules.md for the citations and the measurements.

// HostDepthLimit is the Soroban host's recursion budget: DEFAULT_HOST_DEPTH_LIMIT
// in rs-soroban-env (soroban-env-host/src/budget/limits.rs:41), the same value
// in host releases 27.0.1, 28.0.2, 29.0.1 and 30.0.1.
//
// The host spends one level of it for every delegate level it reads from a
// CAP-71-01 delegate tree and for every ScVal level it converts to a host
// value, and refuses the entry with Error(Context, ExceededLimit) when the
// budget runs out. ValidateEntry applies the host's arithmetic exactly; see
// RuleDelegateDepth and RuleValueDepth.
const HostDepthLimit = 100

// hostValueDepth reports how many levels of the host's depth budget converting
// v into a host Val consumes.
//
// The host's ScVal-to-Val conversion enters one level of the budget's depth
// limiter for every ScVal it converts (Host::to_host_val,
// soroban-env-host/src/host/conversion.rs:432-441), and a Vec or Map converts
// each of its elements through to_host_val again (conversion.rs:549-565). So a
// scalar costs 1, and a container costs 1 plus its deepest element. Map key
// comparisons during construction never go deeper than the keys themselves
// (comparison.rs:298-376), so they add nothing.
//
// The walk stops at limit+1: a result above limit is already a refusal, and
// following a pathological value any further is the thing this guards against.
func hostValueDepth(v xdr.ScVal, limit int) int {
	return hostValueDepthAt(v, 1, limit)
}

func hostValueDepthAt(v xdr.ScVal, depth, limit int) int {
	if depth > limit {
		return depth
	}
	deepest := depth
	switch v.Type {
	case xdr.ScValTypeScvVec:
		if v.Vec == nil || *v.Vec == nil {
			return depth
		}
		for _, element := range **v.Vec {
			deepest = max(deepest, hostValueDepthAt(element, depth+1, limit))
			if deepest > limit {
				return deepest
			}
		}
	case xdr.ScValTypeScvMap:
		if v.Map == nil || *v.Map == nil {
			return depth
		}
		for _, entry := range **v.Map {
			deepest = max(deepest, hostValueDepthAt(entry.Key, depth+1, limit))
			deepest = max(deepest, hostValueDepthAt(entry.Val, depth+1, limit))
			if deepest > limit {
				return deepest
			}
		}
	}
	return deepest
}

// compareScVal orders two ScVals the way the Soroban host does, returning -1,
// 0 or +1.
//
// The host builds a map from an ScMap by checking that each key compares
// strictly less than the next (MeteredOrdMap::from_map,
// soroban-env-host/src/host/metered_map.rs:128-136), using Compare<ScVal>
// (comparison.rs:298-376). That comparison is the derived Ord of the Rust XDR
// ScVal type, which the host asserts in its own compare_obj_to_small test
// (comparison.rs:655): values of different types order by discriminant, and
// values of one type order field by field.
//
// That is NOT the order of the values' XDR bytes, which is why this exists
// rather than a bytes.Compare over MarshalBinary output:
//
//   - signed integers order numerically, so I32(-1) < I32(1), while their XDR
//     bytes order the other way round;
//   - Bytes, String and Symbol order lexicographically with a shorter prefix
//     first, so Bytes{1,0} < Bytes{2}, while XDR's length prefix puts the
//     shorter value first;
//   - Vec and Map order element by element, then by length.
//
// Each of those three cases was checked against soroban-env-host 30.0.1 by
// building a map with the keys in the claimed order and confirming the host
// accepts it; see docs/host-rules.md.
//
// Addresses are the exception that does match the XDR bytes: ScAddress's
// derived Ord compares the discriminant and then fixed-size fields in
// declaration order, which is exactly the XDR encoding's byte order.
//
// The types the host cannot represent as a Val (ContractInstance and the two
// ledger-key types) never reach a host comparison, and Vec or Map with no body
// is refused by the host's comparison itself; both are reported as errors here
// so a caller cannot mistake them for an ordering.
func compareScVal(a, b xdr.ScVal, depth int) (int, error) {
	if depth > HostDepthLimit {
		return 0, fmt.Errorf("value nesting exceeds the host's depth limit of %d", HostDepthLimit)
	}
	if a.Type != b.Type {
		return cmp.Compare(a.Type, b.Type), nil
	}

	switch a.Type {
	case xdr.ScValTypeScvVoid, xdr.ScValTypeScvLedgerKeyContractInstance:
		return 0, nil
	case xdr.ScValTypeScvBool:
		if a.B == nil || b.B == nil {
			return 0, errMissingArm(a.Type)
		}
		return compareBool(*a.B, *b.B), nil
	case xdr.ScValTypeScvError:
		if a.Error == nil || b.Error == nil {
			return 0, errMissingArm(a.Type)
		}
		return compareScError(*a.Error, *b.Error)
	case xdr.ScValTypeScvU32:
		if a.U32 == nil || b.U32 == nil {
			return 0, errMissingArm(a.Type)
		}
		return cmp.Compare(*a.U32, *b.U32), nil
	case xdr.ScValTypeScvI32:
		if a.I32 == nil || b.I32 == nil {
			return 0, errMissingArm(a.Type)
		}
		return cmp.Compare(*a.I32, *b.I32), nil
	case xdr.ScValTypeScvU64:
		if a.U64 == nil || b.U64 == nil {
			return 0, errMissingArm(a.Type)
		}
		return cmp.Compare(*a.U64, *b.U64), nil
	case xdr.ScValTypeScvI64:
		if a.I64 == nil || b.I64 == nil {
			return 0, errMissingArm(a.Type)
		}
		return cmp.Compare(*a.I64, *b.I64), nil
	case xdr.ScValTypeScvTimepoint:
		if a.Timepoint == nil || b.Timepoint == nil {
			return 0, errMissingArm(a.Type)
		}
		return cmp.Compare(*a.Timepoint, *b.Timepoint), nil
	case xdr.ScValTypeScvDuration:
		if a.Duration == nil || b.Duration == nil {
			return 0, errMissingArm(a.Type)
		}
		return cmp.Compare(*a.Duration, *b.Duration), nil
	case xdr.ScValTypeScvU128:
		if a.U128 == nil || b.U128 == nil {
			return 0, errMissingArm(a.Type)
		}
		return cmpChain(cmp.Compare(a.U128.Hi, b.U128.Hi), cmp.Compare(a.U128.Lo, b.U128.Lo)), nil
	case xdr.ScValTypeScvI128:
		if a.I128 == nil || b.I128 == nil {
			return 0, errMissingArm(a.Type)
		}
		// Int128Parts is {hi: i64, lo: u64}: the signed high half first, then
		// the unsigned low half, which is numeric order.
		return cmpChain(cmp.Compare(a.I128.Hi, b.I128.Hi), cmp.Compare(a.I128.Lo, b.I128.Lo)), nil
	case xdr.ScValTypeScvU256:
		if a.U256 == nil || b.U256 == nil {
			return 0, errMissingArm(a.Type)
		}
		return cmpChain(
			cmp.Compare(a.U256.HiHi, b.U256.HiHi), cmp.Compare(a.U256.HiLo, b.U256.HiLo),
			cmp.Compare(a.U256.LoHi, b.U256.LoHi), cmp.Compare(a.U256.LoLo, b.U256.LoLo)), nil
	case xdr.ScValTypeScvI256:
		if a.I256 == nil || b.I256 == nil {
			return 0, errMissingArm(a.Type)
		}
		return cmpChain(
			cmp.Compare(a.I256.HiHi, b.I256.HiHi), cmp.Compare(a.I256.HiLo, b.I256.HiLo),
			cmp.Compare(a.I256.LoHi, b.I256.LoHi), cmp.Compare(a.I256.LoLo, b.I256.LoLo)), nil
	case xdr.ScValTypeScvBytes:
		if a.Bytes == nil || b.Bytes == nil {
			return 0, errMissingArm(a.Type)
		}
		return bytes.Compare(*a.Bytes, *b.Bytes), nil
	case xdr.ScValTypeScvString:
		if a.Str == nil || b.Str == nil {
			return 0, errMissingArm(a.Type)
		}
		return cmp.Compare(string(*a.Str), string(*b.Str)), nil
	case xdr.ScValTypeScvSymbol:
		if a.Sym == nil || b.Sym == nil {
			return 0, errMissingArm(a.Type)
		}
		return cmp.Compare(string(*a.Sym), string(*b.Sym)), nil
	case xdr.ScValTypeScvExecutableTag:
		if a.ExecutableTag == nil || b.ExecutableTag == nil {
			return 0, errMissingArm(a.Type)
		}
		return cmp.Compare(string(*a.ExecutableTag), string(*b.ExecutableTag)), nil
	case xdr.ScValTypeScvAddress:
		if a.Address == nil || b.Address == nil {
			return 0, errMissingArm(a.Type)
		}
		left, err := addressBytes(*a.Address)
		if err != nil {
			return 0, err
		}
		right, err := addressBytes(*b.Address)
		if err != nil {
			return 0, err
		}
		return bytes.Compare(left, right), nil
	case xdr.ScValTypeScvVec:
		if a.Vec == nil || *a.Vec == nil || b.Vec == nil || *b.Vec == nil {
			return 0, fmt.Errorf("a vec with no body has no host ordering")
		}
		left, right := **a.Vec, **b.Vec
		for i := 0; i < len(left) && i < len(right); i++ {
			order, err := compareScVal(left[i], right[i], depth+1)
			if err != nil || order != 0 {
				return order, err
			}
		}
		return cmp.Compare(len(left), len(right)), nil
	case xdr.ScValTypeScvMap:
		if a.Map == nil || *a.Map == nil || b.Map == nil || *b.Map == nil {
			return 0, fmt.Errorf("a map with no body has no host ordering")
		}
		left, right := **a.Map, **b.Map
		for i := 0; i < len(left) && i < len(right); i++ {
			order, err := compareScVal(left[i].Key, right[i].Key, depth+1)
			if err != nil || order != 0 {
				return order, err
			}
			order, err = compareScVal(left[i].Val, right[i].Val, depth+1)
			if err != nil || order != 0 {
				return order, err
			}
		}
		return cmp.Compare(len(left), len(right)), nil
	default:
		return 0, fmt.Errorf("%s values cannot be represented as host values and have no host ordering", a.Type)
	}
}

// compareScError orders ScError the way its derived Ord does: by error type,
// then by the contract code (for the Contract type) or the error code.
func compareScError(a, b xdr.ScError) (int, error) {
	if a.Type != b.Type {
		return cmp.Compare(a.Type, b.Type), nil
	}
	if a.Type == xdr.ScErrorTypeSceContract {
		if a.ContractCode == nil || b.ContractCode == nil {
			return 0, fmt.Errorf("contract error has no contract code")
		}
		return cmp.Compare(*a.ContractCode, *b.ContractCode), nil
	}
	if a.Code == nil || b.Code == nil {
		return 0, fmt.Errorf("error value has no error code")
	}
	return cmp.Compare(*a.Code, *b.Code), nil
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	default:
		return 1
	}
}

// cmpChain returns the first non-zero comparison, which is how a derived Ord
// over a struct's fields in declaration order behaves.
func cmpChain(orders ...int) int {
	for _, order := range orders {
		if order != 0 {
			return order
		}
	}
	return 0
}

func errMissingArm(t xdr.ScValType) error {
	return fmt.Errorf("%s value has no body", t)
}
