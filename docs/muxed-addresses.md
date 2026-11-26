# Muxed Account Handling Audit Across Soroauth

## 1. Executive Summary

This audit enumerates every site in the repository where a Stellar address is
parsed, formatted, or reported, documenting its exact behavior with respect to
muxed accounts (`M…`, SEP-23 / CAP-27).

**Core Principle:**

- **Credentials position** ("who is authorizing"): An address credential
  satisfies `require_auth()` under CAP-46-11. Muxed accounts (`M…`) are
  **strictly refused** by `ParseAddress` and `FormatAddress` rather than
  silently truncated or unwrapped to their underlying `G…` public key. Signing
  must name the exact authorized entity.
- **Arguments position** ("what is being authorized"): Invocations can
  legitimately pass muxed accounts as arguments (e.g. transfer destination). In
  arguments, muxed accounts are **reported in full (`M…`) and never truncated**
  to their underlying `G…` account, because dropping or truncating a muxed
  recipient hides routing information and introduces critical security risks.

---

## 2. Address Handling Sites Enumeration

| File              | Function / Site            | Role                                      | Muxed (`M…`) Behavior                                                | Rationale & Host Rule Citation                                                                        |
| ----------------- | -------------------------- | ----------------------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `address.go`      | `ParseAddress`             | Parses strkey string to `xdr.ScAddress`   | **Refused** (returns error)                                          | Credentials rule: only `G…` and `C…` can authorize Soroban credentials (CAP-46-11, CAP-71-01).        |
| `address.go`      | `FormatAddress`            | Formats `xdr.ScAddress` to strkey string  | **Refused** for `ScAddressTypeScAddressTypeMuxedAccount`             | Ensures credentials formatting never emits an `M…` address.                                           |
| `address.go`      | `FormatMuxedAccount`       | Formats `xdr.MuxedEd25519Account`         | **Formatted in full** as 69-char `M…` strkey                         | SEP-23 / CAP-27: 32 bytes Ed25519 public key + 8 bytes uint64 big-endian ID.                          |
| `address.go`      | `FormatArgumentAddress`    | Formats `xdr.ScAddress` in arguments      | **Formatted in full**: `G…`, `C…`, or `M…`                           | Argument values must preserve full destination/recipient identity without loss.                       |
| `address.go`      | `FormatScVal`              | Formats `xdr.ScVal` for reports and diffs | **Formatted in full** via `FormatArgumentAddress`                    | Any address argument is displayed in full, preserving `M…` strkeys.                                   |
| `diff.go`         | `diffContractFn`           | Compares invocation arguments             | **Diffed and reported in full**                                      | Any argument difference involving a muxed address renders both `From` and `To` with full `M…` strkey. |
| `canonical.go`    | `encodeCanonicalAddress`   | Canonical JSON serialization              | **Emits `muxed_account` with full `M…`**                             | Arguments encoded canonically preserve muxed account strkeys.                                         |
| `inspect.go`      | `Inspect`                  | Inspects authorization entry              | Credentials refuse `M…`; argument addresses keep full representation | Structural inspection of credential signer addresses vs. invocation payload.                          |
| `treerender.go`   | `RenderInvocationWithArgs` | Renders invocation tree with arguments    | **Renders arguments with full `M…`**                                 | Terminal / text tree views show full muxed recipient addresses in arguments.                          |
| `policy/rules.go` | `ContractAllowlistRule`    | Validates target contract addresses       | Refuses `M…` for contracts                                           | Contracts can only be `C…` addresses.                                                                 |
| `arm.go`          | Credential setters         | Assigns signer address to credential arms | Refuses `M…`                                                         | Credential signers cannot be muxed accounts.                                                          |
| `verify.go`       | `VerifyEntry`              | Verifies cryptographic signatures         | Refuses `M…` for credential signers                                  | Signers must be Ed25519 public keys or contracts.                                                     |
