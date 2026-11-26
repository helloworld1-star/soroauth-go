package soroauth

import (
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// scAddressPayloadLen is the raw payload length, in bytes, of both an ed25519
// account address and a contract address. strkey.DecodeAny already enforces the
// SEP-23 payload length for the version bytes accepted here; the length is
// re-checked at the copy so that a future version byte sharing one of these
// arms can never be silently truncated into a valid-looking address.
const scAddressPayloadLen = 32

// ParseAddress converts a G… account strkey or a C… contract strkey into the
// xdr.ScAddress that names it.
//
// Only those two forms are accepted for credentials. An M… muxed address is
// rejected rather than unwrapped to the account it wraps: a Soroban address
// credential names the identity whose require_auth() is being satisfied
// (CAP-46-11), and unwrapping would mean signing on behalf of an identity the
// caller did not write down. Every other strkey form (seeds, signed payloads,
// liquidity pools, claimable balances) names something that cannot appear in an
// address credential at all.
//
// This rejection applies only to the *credentials* position — the "who
// authorizes" half of an entry. A muxed address is legal inside *invocation
// arguments* (the "what is being authorized" half), because an argument is data
// being approved, not an identity authorizing. The XDR ScVal/ScAddress union
// represents muxed addresses in arguments without restriction.
//
// Only the canonical SEP-23 base32 spelling of an address is accepted: upper
// case A-Z and 2-7, no padding, no surrounding whitespace, no extra characters,
// and any unused trailing bits set to zero. A strkey that decodes to the right
// version byte and payload but is not that canonical spelling — lower-cased,
// padded, wrapped in whitespace, or carrying non-zero unused bits — is refused,
// so a caller can never be handed a string that means the same bytes here but
// re-encodes differently elsewhere. The rejection is a strkey decoder refusal
// (SEP-23; go-stellar-sdk strkey.decodeString) rather than a check made here.
//
// The returned error wraps strkey's own error for malformed input, so a bad
// checksum is distinguishable from a well-formed address of the wrong kind.
func ParseAddress(s string) (xdr.ScAddress, error) {
	// DecodeAny validates the base32, the CRC-16 checksum, that the version
	// byte is a defined one, and that the payload length matches it.
	version, payload, err := strkey.DecodeAny(s)
	if err != nil {
		return xdr.ScAddress{}, fmt.Errorf("soroauth: parse address: %w", err)
	}

	switch version {
	case strkey.VersionByteAccountID:
		if len(payload) != scAddressPayloadLen {
			return xdr.ScAddress{}, fmt.Errorf(
				"soroauth: parse address: account address has a %d-byte payload, want %d",
				len(payload), scAddressPayloadLen)
		}
		var ed25519 xdr.Uint256
		copy(ed25519[:], payload)
		accountID := xdr.AccountId{
			Type:    xdr.PublicKeyTypePublicKeyTypeEd25519,
			Ed25519: &ed25519,
		}
		return xdr.ScAddress{
			Type:      xdr.ScAddressTypeScAddressTypeAccount,
			AccountId: &accountID,
		}, nil

	case strkey.VersionByteContract:
		if len(payload) != scAddressPayloadLen {
			return xdr.ScAddress{}, fmt.Errorf(
				"soroauth: parse address: contract address has a %d-byte payload, want %d",
				len(payload), scAddressPayloadLen)
		}
		var contractID xdr.ContractId
		copy(contractID[:], payload)
		return xdr.ScAddress{
			Type:       xdr.ScAddressTypeScAddressTypeContract,
			ContractId: &contractID,
		}, nil

	case strkey.VersionByteMuxedAccount:
		return xdr.ScAddress{}, fmt.Errorf(
			"soroauth: parse address: %q is a muxed (M…) address; an address credential must name the "+
				"account itself, so pass the underlying G… address", s)

	default:
		return xdr.ScAddress{}, fmt.Errorf(
			"soroauth: parse address: %q is not an account (G…) or contract (C…) address", s)
	}
}

// FormatAddress is the inverse of ParseAddress: it renders an xdr.ScAddress as
// the strkey that names it.
//
// It accepts exactly what ParseAddress produces, so ParseAddress and
// FormatAddress round-trip. Arms that ParseAddress refuses to build — muxed
// accounts, claimable balances, liquidity pools — are refused here too rather
// than rendered, so a caller can never be shown an address that this library
// would decline to sign for.
//
// To format an address that may legitimately appear in invocation arguments
// (including muxed accounts formatted in full as M…), use FormatArgumentAddress.
func FormatAddress(a xdr.ScAddress) (string, error) {
	switch a.Type {
	case xdr.ScAddressTypeScAddressTypeAccount:
		if a.AccountId == nil {
			return "", fmt.Errorf("soroauth: format address: account arm has no account id")
		}
		address, err := a.AccountId.GetAddress()
		if err != nil {
			return "", fmt.Errorf("soroauth: format address: %w", err)
		}
		return address, nil

	case xdr.ScAddressTypeScAddressTypeContract:
		if a.ContractId == nil {
			return "", fmt.Errorf("soroauth: format address: contract arm has no contract id")
		}
		address, err := strkey.Encode(strkey.VersionByteContract, a.ContractId[:])
		if err != nil {
			return "", fmt.Errorf("soroauth: format address: %w", err)
		}
		return address, nil

	case xdr.ScAddressTypeScAddressTypeMuxedAccount:
		return "", fmt.Errorf(
			"soroauth: format address: muxed (M…) addresses are not valid in an address credential")

	default:
		return "", fmt.Errorf(
			"soroauth: format address: unsupported address type %d", a.Type)
	}
}

// FormatMuxedAccount encodes a muxed account (id + ed25519) into its full M… strkey string.
func FormatMuxedAccount(muxed *xdr.MuxedEd25519Account) (string, error) {
	if muxed == nil {
		return "", fmt.Errorf("soroauth: format muxed account: nil muxed account")
	}
	// Payload for VersionByteMuxedAccount is 32 bytes ed25519 + 8 bytes uint64 big-endian ID
	var payload [40]byte
	copy(payload[:32], muxed.Ed25519[:])
	binaryBigEndianPutUint64(payload[32:], uint64(muxed.Id))
	str, err := strkey.Encode(strkey.VersionByteMuxedAccount, payload[:])
	if err != nil {
		return "", fmt.Errorf("soroauth: format muxed account: %w", err)
	}
	return str, nil
}

func binaryBigEndianPutUint64(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

// parseMuxedAddress decodes an M… strkey back into an xdr.ScAddress with
// ScAddressTypeScAddressTypeMuxedAccount. This is the inverse of FormatMuxedAccount
// and is used by the canonical JSON decoder for muxed_account addresses.
func parseMuxedAddress(muxedStr string) (xdr.ScAddress, error) {
	payload, err := strkey.Decode(strkey.VersionByteMuxedAccount, muxedStr)
	if err != nil {
		return xdr.ScAddress{}, fmt.Errorf("soroauth: parse muxed address: %w", err)
	}
	if len(payload) != 40 {
		return xdr.ScAddress{}, fmt.Errorf("soroauth: parse muxed address: unexpected payload length %d", len(payload))
	}
	var ed25519 xdr.Uint256
	copy(ed25519[:], payload[:32])
	muxedID := uint64(payload[32])<<56 | uint64(payload[33])<<48 |
		uint64(payload[34])<<40 | uint64(payload[35])<<32 |
		uint64(payload[36])<<24 | uint64(payload[37])<<16 |
		uint64(payload[38])<<8 | uint64(payload[39])
	muxed := xdr.MuxedEd25519Account{
		Ed25519: ed25519,
		Id:      xdr.Uint64(muxedID),
	}
	return xdr.ScAddress{
		Type:         xdr.ScAddressTypeScAddressTypeMuxedAccount,
		MuxedAccount: &muxed,
	}, nil
}

// FormatArgumentAddress formats an xdr.ScAddress that appears inside invocation arguments.
//
// Unlike FormatAddress (which is for credentials and strictly refuses M…),
// FormatArgumentAddress formats muxed accounts into their full M… strkey representation
// without truncation or converting to the underlying G… account. Account (G…) and
// Contract (C…) addresses format identically to FormatAddress.
func FormatArgumentAddress(a xdr.ScAddress) (string, error) {
	switch a.Type {
	case xdr.ScAddressTypeScAddressTypeAccount, xdr.ScAddressTypeScAddressTypeContract:
		return FormatAddress(a)
	case xdr.ScAddressTypeScAddressTypeMuxedAccount:
		if a.MuxedAccount == nil {
			return "", fmt.Errorf("soroauth: format argument address: muxed account arm has no account data")
		}
		return FormatMuxedAccount(a.MuxedAccount)
	default:
		return "", fmt.Errorf("soroauth: format argument address: unsupported address type %d", a.Type)
	}
}

// FormatScVal formats an ScVal into a human-readable representation for reports, diffs,
// and inspectors. Crucially, when an ScVal is an address (including muxed accounts),
// it formats it in full via FormatArgumentAddress.
func FormatScVal(v xdr.ScVal) string {
	switch v.Type {
	case xdr.ScValTypeScvAddress:
		if v.Address != nil {
			if str, err := FormatArgumentAddress(*v.Address); err == nil {
				return str
			}
		}
		return "ScvAddress"
	case xdr.ScValTypeScvBool:
		if v.B != nil {
			return fmt.Sprintf("%t", *v.B)
		}
	case xdr.ScValTypeScvU32:
		if v.U32 != nil {
			return fmt.Sprintf("%d", *v.U32)
		}
	case xdr.ScValTypeScvI32:
		if v.I32 != nil {
			return fmt.Sprintf("%d", *v.I32)
		}
	case xdr.ScValTypeScvU64:
		if v.U64 != nil {
			return fmt.Sprintf("%d", *v.U64)
		}
	case xdr.ScValTypeScvI64:
		if v.I64 != nil {
			return fmt.Sprintf("%d", *v.I64)
		}
	case xdr.ScValTypeScvSymbol:
		if v.Sym != nil {
			return string(*v.Sym)
		}
	case xdr.ScValTypeScvString:
		if v.Str != nil {
			return fmt.Sprintf("%q", string(*v.Str))
		}
	case xdr.ScValTypeScvBytes:
		if v.Bytes != nil && *v.Bytes != nil {
			return fmt.Sprintf("bytes[%d]", len(*v.Bytes))
		}
	case xdr.ScValTypeScvVec:
		if v.Vec != nil && *v.Vec != nil {
			items := make([]string, len(**v.Vec))
			for i, elem := range **v.Vec {
				items[i] = FormatScVal(elem)
			}
			return fmt.Sprintf("[%s]", strings.Join(items, ", "))
		}
	case xdr.ScValTypeScvVoid:
		return "void"
	}
	return v.Type.String()
}
