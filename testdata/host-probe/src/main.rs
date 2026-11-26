//! Prints the measurements docs/host-rules.md records.

use soroauth_host_probe::*;
use soroban_env_host::xdr::ScVal;

fn main() {
    for (label, signature) in [
        ("void", ScVal::Void),
        ("empty-vec", vec(vec![])),
        ("ed25519", ed25519_signature()),
    ] {
        let (depth, err) = max_delegate_depth(&signature);
        println!("{label} delegate sigs: max accepted delegate depth = {depth}; depth {} rejected with {err}", depth + 1);
    }
    for width in [1u32, 10, 100, 1000, 5000] {
        let (bytes, cpu, mem, accepted) = breadth_cost(width);
        println!("breadth {width}: accepted={accepted} entry_xdr_bytes={bytes} cpu_insns={cpu} mem_bytes={mem}");
    }
}
