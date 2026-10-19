package soroauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

var (
	// ErrWrongNetwork is returned when a signer pinned to a specific network
	// passphrase receives a preimage built for a different network.
	ErrWrongNetwork = errors.New("signer refused payload for the wrong network")
)

type networkPinnedSigner struct {
	inner      Signer
	passphrase string
	expectedID [32]byte
}

// PinSignerToNetwork returns a Signer wrapper that pins inner to the given
// network passphrase. Any call to Sign with a preimage belonging to a different
// network ID is refused with ErrWrongNetwork. If the source-account arm or another
// arm lacking a preimage is encountered, it is handled explicitly.
func PinSignerToNetwork(inner Signer, networkPassphrase string) (Signer, error) {
	if inner == nil {
		return nil, fmt.Errorf("soroauth: pin signer: %w", ErrMissingSigner)
	}
	id := network.ID(networkPassphrase)
	return &networkPinnedSigner{
		inner:      inner,
		passphrase: networkPassphrase,
		expectedID: id,
	}, nil
}

// PinSigner is an alias for PinSignerToNetwork.
func PinSigner(signer Signer, passphrase string) (Signer, error) {
	return PinSignerToNetwork(signer, passphrase)
}

func (p *networkPinnedSigner) Address() string {
	return p.inner.Address()
}

func (p *networkPinnedSigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: network pinned signer: %w", err)
	}

	var gotID [32]byte
	switch preimage.Type {
	case xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization:
		if preimage.SorobanAuthorization == nil {
			return xdr.ScVal{}, fmt.Errorf("soroauth: network pinned signer: nil soroban authorization preimage: %w", ErrWrongNetwork)
		}
		gotID = preimage.SorobanAuthorization.NetworkId
	case xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorizationWithAddress:
		if preimage.SorobanAuthorizationWithAddress == nil {
			return xdr.ScVal{}, fmt.Errorf("soroauth: network pinned signer: nil soroban authorization with address preimage: %w", ErrWrongNetwork)
		}
		gotID = preimage.SorobanAuthorizationWithAddress.NetworkId
	default:
		// Source account or any arm without a preimage is handled explicitly
		return xdr.ScVal{}, fmt.Errorf("soroauth: network pinned signer: unsupported or missing preimage type for network check: %w", ErrWrongNetwork)
	}

	if !bytes.Equal(gotID[:], p.expectedID[:]) {
		return xdr.ScVal{}, fmt.Errorf(
			"soroauth: network pinned signer: network ID mismatch (got %x, want %x): %w",
			gotID,
			p.expectedID,
			ErrWrongNetwork,
		)
	}

	return p.inner.Sign(ctx, preimage, payload)
}
