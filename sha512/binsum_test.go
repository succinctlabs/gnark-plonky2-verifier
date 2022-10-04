package sha512

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	// "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type BinsumTest struct {
	A []frontend.Variable
	B []frontend.Variable
	C []frontend.Variable
}

func (c *BinsumTest) Define(api frontend.API) error {
	sum := BinSum(api, c.A, c.B)
	for i := 0; i < len(sum) || i < len(c.C); i++ {
		if i < len(sum) && i < len(c.C) {
			api.AssertIsEqual(sum[i], c.C[i])
		} else if i < len(sum) {
			api.AssertIsEqual(sum[i], 0)
		} else {
			api.AssertIsEqual(c.C[i], 0)
		}
	}
	return nil
}

func TestBinsum(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := BinsumTest{
		A: []frontend.Variable{0, 0, 0},
		B: []frontend.Variable{0, 0, 0},
		C: []frontend.Variable{0, 0, 0, 0},
	}
	witness := BinsumTest{
		A: []frontend.Variable{1, 0, 1},
		B: []frontend.Variable{1, 1, 1},
		C: []frontend.Variable{0, 0, 1, 1},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

var testCurve = ecc.BN254
