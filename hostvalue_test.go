package soroauth

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

func u32Val(v uint32) xdr.ScVal {
	x := xdr.Uint32(v)
	return xdr.ScVal{Type: xdr.ScValTypeScvU32, U32: &x}
}

func i32Val(v int32) xdr.ScVal {
	x := xdr.Int32(v)
	return xdr.ScVal{Type: xdr.ScValTypeScvI32, I32: &x}
}

func i64Val(v int64) xdr.ScVal {
	x := xdr.Int64(v)
	return xdr.ScVal{Type: xdr.ScValTypeScvI64, I64: &x}
}

func i128Val(hi int64, lo uint64) xdr.ScVal {
	x := xdr.Int128Parts{Hi: xdr.Int64(hi), Lo: xdr.Uint64(lo)}
	return xdr.ScVal{Type: xdr.ScValTypeScvI128, I128: &x}
}

func bytesVal(b ...byte) xdr.ScVal {
	x := xdr.ScBytes(b)
	return xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &x}
}

func strVal(s string) xdr.ScVal {
	x := xdr.ScString(s)
	return xdr.ScVal{Type: xdr.ScValTypeScvString, Str: &x}
}

func boolVal(b bool) xdr.ScVal {
	return xdr.ScVal{Type: xdr.ScValTypeScvBool, B: &b}
}

func voidVal() xdr.ScVal { return xdr.ScVal{Type: xdr.ScValTypeScvVoid} }

func mapVal(entries ...xdr.ScMapEntry) xdr.ScVal {
	m := xdr.ScMap(entries)
	p := &m
	return xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &p}
}

func addressVal(t *testing.T, strkey string) xdr.ScVal {
	t.Helper()
	address := mustParse(t, strkey)
	return xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &address}
}

// nestedVec returns a value whose host depth is exactly depth: depth-1 vectors
// wrapped around a Void.
func nestedVec(depth int) xdr.ScVal {
	value := voidVal()
	for i := 1; i < depth; i++ {
		value = scVec(value)
	}
	return value
}

// TestCompareScValMatchesHostOrder pins compareScVal to the host's order.
//
// The three cases marked "host-checked" were confirmed against
// soroban-env-host 30.0.1 (and 28.0.2, 29.0.1) by building an ScMap with the
// keys in the claimed order and calling set_authorization_entries on an entry
// carrying it as a signature: the host accepted each one, which it does only
// for strictly ascending keys (metered_map.rs:128-136). They are the cases
// where the host's order differs from the order of the values' XDR bytes, so
// they are the ones a bytes.Compare implementation would get wrong. The rest
// follow from the derived Ord of the Rust XDR types (comparison.rs:298-376).
func TestCompareScValMatchesHostOrder(t *testing.T) {
	g1 := testKeypair(t, "soroauth-order-1").Address()
	g2 := testKeypair(t, "soroauth-order-2").Address()
	if compareBytes(t, mustParse(t, g1), mustParse(t, g2)) > 0 {
		g1, g2 = g2, g1
	}
	contract := testContractAddress(t, "soroauth-order-contract")

	cases := []struct {
		name string
		less xdr.ScVal
		more xdr.ScVal
	}{
		{"host-checked: bytes are lexicographic, not length-first", bytesVal(1, 0), bytesVal(2)},
		{"host-checked: signed i32 is numeric", i32Val(-1), i32Val(1)},
		{"host-checked: different types order by discriminant", u32Val(5), i32Val(1)},
		{"bytes prefix sorts first", bytesVal(1), bytesVal(1, 0)},
		{"signed i64 is numeric", i64Val(-5), i64Val(3)},
		{"i128 negative before positive", i128Val(-1, ^uint64(0)), i128Val(0, 0)},
		{"i128 low half is unsigned", i128Val(0, 1), i128Val(0, ^uint64(0))},
		{"bool false before true", boolVal(false), boolVal(true)},
		{"void before u32", voidVal(), u32Val(0)},
		{"strings lexicographic", strVal("ab"), strVal("b")},
		{"symbols lexicographic", scSymbol("public_key"), scSymbol("signature")},
		{"account address before contract address", addressVal(t, g1), addressVal(t, contract)},
		{"account addresses by key bytes", addressVal(t, g1), addressVal(t, g2)},
		{"vec element-wise before length", scVec(u32Val(1), u32Val(9)), scVec(u32Val(2))},
		{"vec prefix sorts first", scVec(u32Val(1)), scVec(u32Val(1), u32Val(0))},
		{"map compares keys then values", mapVal(xdr.ScMapEntry{Key: u32Val(1), Val: u32Val(1)}),
			mapVal(xdr.ScMapEntry{Key: u32Val(1), Val: u32Val(2)})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := compareScVal(tc.less, tc.more, 1); err != nil || got != -1 {
				t.Errorf("compare(less, more) = %d, %v; want -1", got, err)
			}
			if got, err := compareScVal(tc.more, tc.less, 1); err != nil || got != 1 {
				t.Errorf("compare(more, less) = %d, %v; want 1", got, err)
			}
			if got, err := compareScVal(tc.less, tc.less, 1); err != nil || got != 0 {
				t.Errorf("compare(less, less) = %d, %v; want 0", got, err)
			}
		})
	}

	t.Run("unrepresentable types have no order", func(t *testing.T) {
		nonce := xdr.ScVal{Type: xdr.ScValTypeScvLedgerKeyNonce, NonceKey: &xdr.ScNonceKey{Nonce: 1}}
		if _, err := compareScVal(nonce, nonce, 1); err == nil {
			t.Error("compareScVal ordered two LedgerKeyNonce values; the host cannot")
		}
	})
	t.Run("a vec with no body has no order", func(t *testing.T) {
		var missing *xdr.ScVec
		empty := xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &missing}
		if _, err := compareScVal(empty, empty, 1); err == nil {
			t.Error("compareScVal ordered a vec with no body; the host refuses to")
		}
	})
}

func compareBytes(t *testing.T, a, b xdr.ScAddress) int {
	t.Helper()
	order, err := compareScVal(xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &a},
		xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &b}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return order
}

// TestHostValueDepth pins the depth model to the host's measurements: a Void
// or empty-vector signature costs 1 level and the classic account signature
// costs 3, which is what makes the host refuse a delegate at depth 99 with a
// Void signature and at depth 97 with an ed25519 one (see
// TestHostDelegateDepthMatchesMeasuredBoundaries).
func TestHostValueDepth(t *testing.T) {
	signature, err := Ed25519SignatureScVal(make([]byte, 32), make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		value xdr.ScVal
		want  int
	}{
		{"void", voidVal(), 1},
		{"scalar", u32Val(7), 1},
		{"empty vec", scVec(), 1},
		{"account signature", signature, 3},
		{"map key deeper than value", mapVal(xdr.ScMapEntry{Key: scVec(scVec(voidVal())), Val: voidVal()}), 4},
		{"nested vec of depth 10", nestedVec(10), 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostValueDepth(tc.value, HostDepthLimit); got != tc.want {
				t.Errorf("hostValueDepth = %d, want %d", got, tc.want)
			}
		})
	}

	t.Run("the walk stops just past the limit", func(t *testing.T) {
		if got := hostValueDepth(nestedVec(500), 10); got != 11 {
			t.Errorf("hostValueDepth(depth 500, limit 10) = %d, want 11", got)
		}
	})
}
