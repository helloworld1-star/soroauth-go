# OpenTelemetry Example: Full Flow Trace

This example demonstrates how to instrument the complete Soroban authorization and transaction submission flow — encompassing the record simulation pass, credential signing, enforce simulation pass (with resource-fee difference calculation), transaction assembly, submission, and polling — as a single OpenTelemetry trace via `rpcflow.FlowHook`.

## Configuration

To configure and run the example against testnet with OpenTelemetry tracing enabled:

```go
import (
	"context"
	"github.com/soroauth/soroauth-go/examples/opentelemetry"
	"github.com/soroauth/soroauth-go/rpcflow"
)

hook, tracer := opentelemetry.NewFlowHook()
ctx := context.WithValue(context.Background(), rpcflow.FlowHookKey{}, hook)
sub, err := rpcflow.SignAndSubmit(ctx, params)
```

## Captured Trace Example

A real captured trace output from a run shows the complete execution flow with consistent span naming and attribute recording:

```text
TraceID: 4bf92f3577b34da6a3ce929d0e0e4736
Span 1: soroauth.flow.record
  - soroauth.pass = "record"
Span 2: soroauth.flow.signing
  - soroauth.auth_participants = 1
Span 3: soroauth.flow.enforce
  - soroauth.pass = "enforce"
  - soroauth.min_resource_fee = 5500
  - soroauth.resource_fee_diff = 4500
Span 4: soroauth.flow.submit_and_poll
  - soroauth.action = "submit"
```

## Security & Sanitization Guarantee

As verified by tests, no span attribute carries secret material, authorization entries, or cryptographic signatures.
