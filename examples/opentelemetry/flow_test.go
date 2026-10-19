package opentelemetry

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

type mockRPCClient struct {
	sims int
}

func (m *mockRPCClient) SimulateTransaction(_ context.Context, req rpc.SimulateTransactionRequest) (rpc.SimulateTransactionResponse, error) {
	m.sims++
	encodedData, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{
		Resources: xdr.SorobanResources{
			Footprint: xdr.LedgerKeyFootprint{},
		},
	})
	return rpc.SimulateTransactionResponse{
		TransactionDataXDR: encodedData,
		MinResourceFee:     1000,
	}, nil
}

func (m *mockRPCClient) GetLatestLedger(context.Context) (rpc.GetLatestLedgerResponse, error) {
	return rpc.GetLatestLedgerResponse{Sequence: 100}, nil
}

func (m *mockRPCClient) SendTransaction(_ context.Context, _ rpc.SendTransactionRequest) (rpc.SendTransactionResponse, error) {
	return rpc.SendTransactionResponse{Hash: "abc12345", Status: "PENDING"}, nil
}

func (m *mockRPCClient) PollTransaction(context.Context, string) (rpc.GetTransactionResponse, error) {
	return rpc.GetTransactionResponse{
		TransactionDetails: rpc.TransactionDetails{Status: rpc.TransactionStatusSuccess, Ledger: 101},
	}, nil
}

func TestRunFullFlowAndTelemetry(t *testing.T) {
	seed := sha256.Sum256([]byte("otel-test-payer"))
	payer, _ := keypair.FromRawSeed(seed)
	signerKp, _ := keypair.FromRawSeed(sha256.Sum256([]byte("otel-test-signer")))
	signer := soroauth.NewEd25519Signer(signerKp)

	client := &mockRPCClient{}

	var contractID xdr.ContractId
	for i := range contractID {
		contractID[i] = byte(i)
	}
	op := txnbuild.InvokeHostFunction{
		HostFunction: xdr.HostFunction{
			Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
			InvokeContract: &xdr.InvokeContractArgs{
				ContractAddress: xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &contractID},
				FunctionName:    xdr.ScSymbol("transfer"),
			},
		},
		SourceAccount: payer.Address(),
	}

	_, rootSpan, _, _ := RunFullFlow(context.Background(), client, payer, signer, op, network.TestNetworkPassphrase)

	if err := AssertNoSecretsInSpan(rootSpan); err != nil {
		t.Fatalf("unexpected secret or forbidden term in span attributes: %v", err)
	}

	foundFeeDiff := false
	var checkSpan func(s TraceSpan)
	checkSpan = func(s TraceSpan) {
		if _, ok := s.Attributes["soroban.resource_fee_diff"]; ok {
			foundFeeDiff = true
		}
		for _, child := range s.Children {
			checkSpan(child)
		}
	}
	checkSpan(rootSpan)
	if !foundFeeDiff {
		t.Fatal("expected soroban.resource_fee_diff attribute in trace")
	}
}
