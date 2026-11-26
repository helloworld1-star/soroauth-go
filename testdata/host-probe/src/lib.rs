//! Builders and probes over the real Soroban host.
//!
//! Every probe goes through `Host::metered_from_xdr` and
//! `Host::set_authorization_entries`, which is exactly what the host does with
//! a transaction's authorization entries before running it
//! (soroban-env-host/src/e2e_invoke.rs:522-527). A delegate tree, a signature
//! or an argument the host refuses there is refused on chain, after the
//! transaction has paid its fee.

use soroban_env_host::budget::AsBudget;
use soroban_env_host::xdr::{
    AccountId, ContractId, Hash, InvokeContractArgs, Limits, PublicKey, ScAddress, ScBytes, ScMap,
    ScMapEntry, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
    SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanDelegateSignature, Uint256, WriteXdr,
};
use soroban_env_host::Host;

/// A distinct G account per index.
pub fn account(i: u32) -> ScAddress {
    let mut key = [0u8; 32];
    key[..4].copy_from_slice(&i.to_be_bytes());
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key))))
}

pub fn symbol(s: &str) -> ScVal {
    ScVal::Symbol(ScSymbol(s.try_into().unwrap()))
}

pub fn bytes(b: &[u8]) -> ScVal {
    ScVal::Bytes(ScBytes(b.to_vec().try_into().unwrap()))
}

pub fn map(entries: Vec<(ScVal, ScVal)>) -> ScVal {
    let entries: Vec<ScMapEntry> = entries
        .into_iter()
        .map(|(key, val)| ScMapEntry { key, val })
        .collect();
    ScVal::Map(Some(ScMap(entries.try_into().unwrap())))
}

pub fn vec(values: Vec<ScVal>) -> ScVal {
    ScVal::Vec(Some(ScVec(values.try_into().unwrap())))
}

/// The classic account signature shape soroauth's ed25519 signers write: a
/// vector holding one {public_key, signature} map.
pub fn ed25519_signature() -> ScVal {
    vec(vec![map(vec![
        (symbol("public_key"), bytes(&[1u8; 32])),
        (symbol("signature"), bytes(&[2u8; 64])),
    ])])
}

/// A single-path delegate tree `depth` levels deep, each level carrying
/// `signature`.
pub fn chain(depth: u32, signature: &ScVal) -> Vec<SorobanDelegateSignature> {
    let mut nested: Vec<SorobanDelegateSignature> = vec![];
    for level in (1..=depth).rev() {
        nested = vec![SorobanDelegateSignature {
            address: account(level),
            signature: signature.clone(),
            nested_delegates: nested.try_into().unwrap(),
        }];
    }
    nested
}

/// A delegates-arm entry for a fixed account and invocation.
pub fn entry(delegates: Vec<SorobanDelegateSignature>, top: ScVal) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::AddressWithDelegates(
            SorobanAddressCredentialsWithDelegates {
                address_credentials: SorobanAddressCredentials {
                    address: account(999_999),
                    nonce: 1,
                    signature_expiration_ledger: 100,
                    signature: top,
                },
                delegates: delegates.try_into().unwrap(),
            },
        ),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([7; 32]))),
                function_name: ScSymbol("f".try_into().unwrap()),
                args: vec![].try_into().unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        },
    }
}

/// Hands the entry to the host the way a transaction does. Returns the host's
/// error, if any, as `Error(Type, Code)`.
pub fn host_accepts(e: &SorobanAuthorizationEntry) -> Result<(), String> {
    let host = Host::test_host();
    let encoded = e.to_xdr(Limits::none()).unwrap();
    let decoded: SorobanAuthorizationEntry = host
        .metered_from_xdr(&encoded)
        .map_err(|err| format!("{:?}", err.error))?;
    host.set_authorization_entries(vec![decoded])
        .map_err(|err| format!("{:?}", err.error))
}

/// The deepest single-path delegate chain the host accepts with `signature`
/// at every level, and the error it gives one level deeper.
pub fn max_delegate_depth(signature: &ScVal) -> (u32, String) {
    let mut accepted = 0;
    for depth in 1..=200 {
        match host_accepts(&entry(chain(depth, signature), ScVal::Void)) {
            Ok(()) => accepted = depth,
            Err(err) => return (accepted, err),
        }
    }
    (accepted, "no refusal up to 200".into())
}

/// What a flat delegates array of `width` ed25519-signed delegates costs the
/// host to read, with an unlimited budget: (encoded entry bytes, CPU
/// instructions, memory bytes, accepted).
pub fn breadth_cost(width: u32) -> (usize, u64, u64, bool) {
    let delegates: Vec<SorobanDelegateSignature> = (1..=width)
        .map(|i| SorobanDelegateSignature {
            address: account(i),
            signature: ed25519_signature(),
            nested_delegates: vec![].try_into().unwrap(),
        })
        .collect();
    let encoded = entry(delegates, ScVal::Void)
        .to_xdr(Limits::none())
        .unwrap();
    let host = Host::test_host();
    host.as_budget().reset_unlimited().unwrap();
    let accepted = host
        .metered_from_xdr::<SorobanAuthorizationEntry>(&encoded)
        .and_then(|decoded| host.set_authorization_entries(vec![decoded]))
        .is_ok();
    let budget = host.as_budget();
    (
        encoded.len(),
        budget.get_cpu_insns_consumed().unwrap(),
        budget.get_mem_bytes_consumed().unwrap(),
        accepted,
    )
}

/// An entry whose top-level signature is `signature`, for the value rules.
pub fn with_top_signature(signature: ScVal) -> SorobanAuthorizationEntry {
    entry(vec![], signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXCEEDED: &str = "Error(Context, ExceededLimit)";

    // docs/host-rules.md and soroauth's TestHostDelegateDepthMatchesMeasuredBoundaries
    // state these numbers; this is where they come from.
    #[test]
    fn delegate_depth_boundary_void() {
        assert_eq!(max_delegate_depth(&ScVal::Void), (98, EXCEEDED.to_string()));
    }

    #[test]
    fn delegate_depth_boundary_empty_vec() {
        assert_eq!(max_delegate_depth(&vec(vec![])), (98, EXCEEDED.to_string()));
    }

    #[test]
    fn delegate_depth_boundary_ed25519() {
        assert_eq!(
            max_delegate_depth(&ed25519_signature()),
            (96, EXCEEDED.to_string())
        );
    }

    #[test]
    fn breadth_has_no_count_limit() {
        let (_, _, _, accepted) = breadth_cost(5000);
        assert!(accepted, "the host refused 5000 delegates in one array");
    }

    #[test]
    fn delegates_must_be_sorted_and_unique() {
        let unsorted = vec![
            SorobanDelegateSignature {
                address: account(2),
                signature: ScVal::Void,
                nested_delegates: vec![].try_into().unwrap(),
            },
            SorobanDelegateSignature {
                address: account(1),
                signature: ScVal::Void,
                nested_delegates: vec![].try_into().unwrap(),
            },
        ];
        assert_eq!(
            host_accepts(&entry(unsorted, ScVal::Void)),
            Err("Error(Auth, InvalidInput)".into())
        );
        let duplicate = vec![
            SorobanDelegateSignature {
                address: account(1),
                signature: ScVal::Void,
                nested_delegates: vec![].try_into().unwrap(),
            },
            SorobanDelegateSignature {
                address: account(1),
                signature: ScVal::Void,
                nested_delegates: vec![].try_into().unwrap(),
            },
        ];
        assert_eq!(
            host_accepts(&entry(duplicate, ScVal::Void)),
            Err("Error(Auth, InvalidInput)".into())
        );
    }

    #[test]
    fn map_keys_use_the_host_order_not_xdr_byte_order() {
        // Each map is strictly ascending in the host's order; the host accepts
        // a map only when it is.
        assert_eq!(
            host_accepts(&with_top_signature(map(vec![
                (bytes(&[1, 0]), ScVal::Void),
                (bytes(&[2]), ScVal::Void)
            ]))),
            Ok(())
        );
        assert_eq!(
            host_accepts(&with_top_signature(map(vec![
                (ScVal::I32(-1), ScVal::Void),
                (ScVal::I32(1), ScVal::Void)
            ]))),
            Ok(())
        );
        assert_eq!(
            host_accepts(&with_top_signature(map(vec![
                (ScVal::U32(5), ScVal::Void),
                (ScVal::I32(1), ScVal::Void)
            ]))),
            Ok(())
        );
        // The same keys reversed are refused.
        assert_eq!(
            host_accepts(&with_top_signature(map(vec![
                (bytes(&[2]), ScVal::Void),
                (bytes(&[1, 0]), ScVal::Void)
            ]))),
            Err("Error(Object, InvalidInput)".into())
        );
    }

    #[test]
    fn value_form_rules() {
        assert!(host_accepts(&with_top_signature(ScVal::Vec(None))).is_err());
        assert!(host_accepts(&with_top_signature(symbol("ok_symbol"))).is_ok());
        assert_eq!(
            host_accepts(&with_top_signature(ScVal::Symbol(ScSymbol(
                "a-b".try_into().unwrap()
            )))),
            Err("Error(Value, InvalidInput)".into())
        );
    }
}
