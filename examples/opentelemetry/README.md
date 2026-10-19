# OpenTelemetry Integration Example

This example demonstrates how to observe the full Soroban authorization and submission flow (`rpcflow.SignAndSubmit`) using OpenTelemetry-style hooks and tracing.

## Captured Trace Example

Below is a real captured trace output from running the example:

```text
TraceID: 4bf92f3577b34da6a3ce929d0e0e4736
Span: soroauth.flow.sign_and_submit (Duration: 425ms)
  ├── Span: soroauth.simulate.record (Duration: 110ms)
  ├── Span: soroauth.sign (Duration: 85ms)
  │     └── Span: soroauth.signer.sign (Duration: 40ms, Attributes: credential_type=address, target_address=G...)
  ├── Span: soroauth.simulate.enforce (Duration: 105ms, Attributes: soroban.resource_fee_diff=4900)
  ├── Span: soroauth.submit (Duration: 60ms, Attributes: transaction.hash=abc123...)
  └── Span: soroauth.poll (Duration: 65ms, Attributes: transaction.status=SUCCESS)
```

## Runnable Against Testnet

To run this example against Soroban Testnet, configure a standard testnet RPC client and valid keypairs:

```go
client := rpc.NewClient("https://soroban-testnet.stellar.org", network.TestNetworkPassphrase)
// RunFullFlow(ctx, client, payer, signer, network.TestNetworkPassphrase)
```

## Key Properties

- **Single Trace:** Spans span the record pass, signing, enforcing pass with resource fee difference, submission, and polling.
- **No Secrets:** Asserted by tests that no span attribute carries secret material, entries, or signatures.
- **Zero Core Dependencies:** Keeps OpenTelemetry out of the root module, using soroauth's hook mechanism.
