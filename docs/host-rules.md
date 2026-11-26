# Host rules

Every rule the Soroban host enforces on an authorization entry that soroauth
knows of, where in the host it is enforced, and whether soroauth can check it
before signing. It is the human-readable copy of `HostRules()`: the two are
compared by `TestHostRulesDocumentMatchesCode`, so a rule added to one and not
the other fails CI.

`ValidateEntry` is the single place every offline rule is checked.
`AuthorizeEntry` and `StreamingSign` call it before any signer runs, and again
on the signed result before returning it, so an entry the host would refuse for
its ordering or canonical form fails locally with `ErrHostRuleViolation` (as a
`*HostRuleError` naming the rule and the path) instead of on chain after the fee
is paid.

## Which host

The citations are to `soroban-env-host` 30.0.1 and `soroban-env-common` 30.0.1,
the host Stellar testnet runs: on 2026-11-25 its RPC reported
`"captiveCoreVersion":"stellar-core 30.0.0 …","protocolVersion":30`. The code
these rules come from — the delegate tree reader, the ScVal-to-Val conversion,
the value comparison, the map constructor, the depth limiter and the classic
account check — has no behavioural difference across 27.0.1, 28.0.2, 29.0.1 and
30.0.1. The one change between 29 and 30 in this area is that protocol 30 also
accepts a muxed contract address inside a value; go-stellar-sdk v0.7.3 has no
such address type, so soroauth can neither produce nor decode one.

The numbers below were not inferred from the source alone. `make host-probe`
runs the real host (`testdata/host-probe`, pinned
`soroban-env-host = "=30.0.1"`) over the same entries, and its tests assert
every boundary this page states.

## The rules

| Rule                      | Offline | What the host requires                                                                                                                           | Where (soroban-env-host 30.0.1 unless stated)                                                                                  | Why it cannot be checked offline                                     |
| ------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| `delegate-order`          | yes     | Each delegates array, at every depth, is in strictly ascending address order.                                                                    | soroban-env-host/src/auth.rs:2163-2193 (DelegatedAccountAuthSignerTreeNode::from_xdr); ScAddress order: host/comparison.rs:193 |                                                                      |
| `delegate-unique`         | yes     | No address repeats within one delegates array; the same address at different depths is allowed.                                                  | soroban-env-host/src/auth.rs:2176-2183                                                                                         |                                                                      |
| `delegate-depth`          | yes     | A delegate at depth k with signature s needs k + 1 + depth(s) <= 100; soroauth also caps k at MaxDelegateDepth (54).                             | soroban-env-host/src/auth.rs:2163, 2197 and 2209; host/conversion.rs:432-441; budget/limits.rs:41 and 83-93                    |                                                                      |
| `value-depth`             | yes     | Every signature, argument and constructor argument value has depth(v) <= 100 when converted at the top of the host's budget.                     | soroban-env-host/src/host/conversion.rs:432-441 and 549-565; auth.rs:809, 2437, 2446 and 2457; account_contract.rs:111         |                                                                      |
| `map-key-order`           | yes     | Every map's keys are strictly ascending in the host's value order (derived Ord of ScVal), so no key repeats.                                     | soroban-env-host/src/host/metered_map.rs:128-136; host/comparison.rs:298-376 and 655; host/conversion.rs:556-565               |                                                                      |
| `value-form`              | yes     | No vec or map without a body, and no ContractInstance, LedgerKeyContractInstance or LedgerKeyNonce value.                                        | soroban-env-common/src/val.rs:602-640 (Val::can_represent_scval); soroban-env-common/src/convert.rs:589-600                    |                                                                      |
| `symbol-form`             | yes     | Every symbol, including each invoked function name, is at most 32 bytes of [A-Za-z0-9_].                                                         | soroban-env-host/src/host_object.rs:294-314; soroban-env-common/src/symbol.rs:237-246; auth.rs:808                             |                                                                      |
| `address-type`            | yes     | Credential and delegate addresses are G accounts or C contracts; an address value is an account, contract or muxed account.                      | soroban-env-host/src/auth.rs:2769-2774 and 1098-1104; host/conversion.rs:624-641                                               |                                                                      |
| `account-signature`       | yes     | A signed classic-account node carries 1 to 20 {public_key, signature} maps with strictly ascending public keys.                                  | soroban-env-host/src/builtin_contracts/account_contract.rs:25, 64-67 and 181-213                                               |                                                                      |
| `create-contract-auth`    | yes     | An authorized create-contract call names a Wasm or external-reference executable and an address-based contract ID preimage.                      | soroban-env-host/src/builtin_contracts/account_contract.rs:82-104, built for every authentication at auth.rs:2749-2750         |                                                                      |
| `nonce-unused`            | no      | The (address, nonce) pair has not been consumed before.                                                                                          | soroban-env-host/src/auth.rs:3058-3063                                                                                         | needs ledger state                                                   |
| `expiration-not-passed`   | no      | The current ledger is not past the signature expiration ledger.                                                                                  | soroban-env-host/src/auth.rs:2663-2673                                                                                         | needs the current ledger                                             |
| `expiration-not-too-late` | no      | The signature expiration ledger does not exceed max_live_until_ledger.                                                                           | soroban-env-host/src/auth.rs:2675-2686                                                                                         | needs the network's state archival settings                          |
| `account-weight`          | no      | Each classic signer belongs to the account and the summed weights meet its medium threshold.                                                     | soroban-env-host/src/builtin_contracts/account_contract.rs:224-263                                                             | needs the account's ledger entry                                     |
| `delegate-use`            | no      | A delegate is matched only by the account contract's delegate_auth call for it, at most once per frame, and must carry a signature when matched. | soroban-env-host/src/auth.rs:1070-1080 and 2316-2356                                                                           | depends on what the account contract's __check_auth does at run time |
| `call-depth`              | no      | The contract call stack during authentication, including nested delegated authentication, stays within the host depth limit.                     | soroban-env-host/src/host/frame.rs:476                                                                                         | depends on the call stack at the moment of authentication            |
| `resource-limits`         | no      | The transaction fits the network's size, instruction and memory limits; the host has no count limit on delegates per array.                      | soroban-env-host/src/auth.rs:2164 and 2205-2211 walk every delegate with no count check; each node is metered                  | the limits are network configuration settings                        |

Notes on reading the table:

- **Unsigned nodes are not a violation.** A Void or empty-vector placeholder is
  what a node looks like before it is signed. An empty vector left on a classic
  account node is refused on chain ("no account signatures found",
  account_contract.rs:196); `RequireFullySigned` is the check for that.
- **Signature validity is not a host _rule_ in this sense.** Whether an ed25519
  signature verifies is checked offline by `VerifyEntry`, which is a separate
  question from whether the entry is well formed.
- **The host's value order is not XDR byte order.** It is the derived `Ord` of
  the Rust XDR `ScVal` type, which the host asserts against its own comparison
  in `compare_obj_to_small` (comparison.rs:655). Signed integers order
  numerically, and bytes, strings and symbols order lexicographically with a
  shorter prefix first, so `I32(-1) < I32(1)` and `Bytes{1,0} < Bytes{2}` even
  though their XDR bytes order the other way. Addresses are the one case where
  the two agree. The probe confirms each of those cases against the host.

## Delegate tree limits

### Depth

The host reads a CAP-71-01 delegate tree recursively. It enters one level of its
depth budget for the root call and one for each delegate (auth.rs:2163, 2209),
and converts each delegate's signature inside that delegate's level, which
spends one more level per ScVal level (auth.rs:2197, conversion.rs:432-441). The
budget starts at `DEFAULT_HOST_DEPTH_LIMIT = 100` (budget/limits.rs:41) and
entering with none left fails with `Error(Context, ExceededLimit)`
(limits.rs:83-93). So a delegate at depth k (the top-level array is depth 1)
with signature s is read only when

```
k + 1 + depth(s) <= 100
```

where a scalar or Void has depth 1 and a vec or map has depth 1 plus its deepest
element. The classic account signature soroauth's signers write — a vector
holding one `{public_key, signature}` map — has depth 3.

Measured with `make host-probe` against soroban-env-host 30.0.1 (the same output
from 28.0.2 and 29.0.1):

```
void delegate sigs: max accepted delegate depth = 98; depth 99 rejected with Error(Context, ExceededLimit)
empty-vec delegate sigs: max accepted delegate depth = 98; depth 99 rejected with Error(Context, ExceededLimit)
ed25519 delegate sigs: max accepted delegate depth = 96; depth 97 rejected with Error(Context, ExceededLimit)
```

soroauth applies one delegate-depth policy, `MaxDelegateDepth = 54`, on every
path: `WithDelegates`, `ValidateEntry`, `AuthorizeEntry` and `StreamingSign`
refuse a deeper tree with `ErrDelegateDepthLimit` before any signer is called.
It is not a free choice. It is the decode bound expressed in delegate levels:
`DecodeAuthorizationEntry` refuses XDR nested past `MaxDecodeDepth = 64`, each
delegate level costs one go-xdr level on top of a fixed overhead, and a signed
leaf costs three more. A fully signed chain of 54 decodes and 55 does not. So
soroauth never signs a tree it could not decode again, and 54 is below the
host's 96, so the host's depth rule never refuses what soroauth signs. A tree
deeper than `MaxDelegateDepth` also matches `ErrDecodeLimit`, which is what such
a tree was refused with before this policy existed.

Below `MaxDelegateDepth`, `ValidateEntry` still applies the host's formula
exactly, because a custom account's signature can be deep enough to overrun the
budget at a shallow delegate. That refusal matches `ErrDelegateDepthLimit` but
not `ErrDecodeLimit`.

| Limit                             | Value | Source                                                                  |
| --------------------------------- | ----- | ----------------------------------------------------------------------- |
| `HostDepthLimit`                  | 100   | `DEFAULT_HOST_DEPTH_LIMIT`, soroban-env-host/src/budget/limits.rs:41    |
| `host-max-delegate-depth-void`    | 98    | measured; the formula with depth(Void) = 1                              |
| `host-max-delegate-depth-ed25519` | 96    | measured; the formula with depth(account signature) = 3                 |
| `MaxDelegateDepth`                | 54    | soroauth policy: the deepest fully signed chain `MaxDecodeDepth` admits |
| `MaxDecodeDepth`                  | 64    | soroauth's untrusted-input decode bound (decode.go)                     |
| `MAX_ACCOUNT_SIGNATURES`          | 20    | soroban-env-host/src/builtin_contracts/account_contract.rs:25           |

`TestHostRulesDocumentMatchesCode` reads this table and compares every value
with the constant or formula it names, and `TestMaxDelegateDepthIsOnePolicy`
proves 54 is exactly the decode bound for a signed chain.

### Breadth

The host has **no limit on how many delegates one array holds**. The tree reader
walks every delegate with no count check (auth.rs:2164, 2205-2211), and the XDR
type is an unbounded array. soroauth therefore does not invent one.

What bounds breadth is the network's resource configuration, which soroauth
cannot know offline: the transaction size limit, and the per-transaction
instruction and memory limits that every delegate is metered against. The cost
of the host reading a flat array of ed25519-signed delegates, measured with
`make host-probe` (soroban-env-host 30.0.1, unlimited budget):

| Delegates | Entry XDR bytes | CPU instructions | Memory bytes |
| --------- | --------------- | ---------------- | ------------ |
| 1         | 340             | 21,041           | 2,374        |
| 10        | 2,320           | 143,515          | 15,532       |
| 100       | 22,120          | 1,368,254        | 147,112      |
| 1,000     | 220,120         | 13,615,651       | 1,462,912    |
| 5,000     | 1,100,120       | 68,048,526       | 7,310,912    |

Each additional ed25519-signed delegate adds 220 bytes to the entry (40 for the
address, 176 for the signature, 4 for its nested array length), about 13,600
instructions and about 1,460 bytes of memory to read. A Void placeholder
delegate is 48 bytes. That is only the cost of reading the tree: every delegate
the account contract actually authenticates adds its own `__check_auth` or
ed25519 verification on top.

For scale, testnet's settings on 2026-11-25 (ledger 5918543, read with
`getLedgerEntries` for the `CONFIG_SETTING_CONTRACT_COMPUTE_V0` and
`CONFIG_SETTING_CONTRACT_BANDWIDTH_V0` entries) were `txMaxSizeBytes=132096`,
`txMaxInstructions=400000000` and `txMemoryLimit=41943040`. The size limit binds
first: fewer than 600 ed25519-signed delegates fit in one transaction, and
reading that many costs about 8 million instructions. These are network settings
that validators can change, which is why they are documentation here and not a
check.

## Testnet confirmation

The e2e scenario `TestScenarioDelegateDepthBoundary` (IDs `S`, `S-host` and
`S-over` in [e2e/RESULTS.md](../e2e/RESULTS.md)) submits three transactions from
a modular account authorized through one delegate, with a Void-signed chain
nested under it:

- `S`: a tree of exactly `MaxDelegateDepth`, built and signed by soroauth, is
  accepted.
- `S-host`: the same tree deepened to the host's limit for a Void signature (98)
  after signing is accepted — the delegate tree is not part of the CAP-71-01
  preimage, so deepening it does not invalidate the signature.
- `S-over`: one level deeper (99) is refused by the host, after the fee, with
  `Error(Context, ExceededLimit)`.

soroauth refuses the `S-host` and `S-over` trees itself before signing; the
scenario asserts that too.
