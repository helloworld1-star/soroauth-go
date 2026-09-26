package xdrcopy

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
	xdrcodec "github.com/stellar/go-xdr/xdr3"
	"github.com/stretchr/testify/require"
)

func (u underConsume) EncodeTo(e *xdrcodec.Encoder) error {
	_, err := e.EncodeUint(u.V)
	return err
}

func (u *underConsume) DecodeFrom(_ *xdrcodec.Decoder, _ uint) (int, error) {
	return 0, nil
}

type underConsume struct{ V uint32 }

var _ xdr.EncoderTo = (*underConsume)(nil)
var _ xdr.DecoderFrom = (*underConsume)(nil)

func FuzzCopy(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		var val xdr.ScAddress
		err := val.UnmarshalBinary(data)
		if err != nil {
			return
		}

		copied, err := Copy(val)
		if err != nil {
			t.Errorf("copy failed: %v", err)
			return
		}

		// Byte-identical check
		origBytes, _ := val.MarshalBinary()
		copyBytes, _ := copied.MarshalBinary()
		require.Equal(t, origBytes, copyBytes)
	})
}
