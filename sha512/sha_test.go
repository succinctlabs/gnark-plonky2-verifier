package sha512

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type Sha512Circuit struct {
	in []frontend.Variable `gnark:"in"`
	out []frontend.Variable `gnark:"out"`
}

func (circuit *Sha512Circuit) Define(api frontend.API) error {
	res := Sha512(api, circuit.in)
	for i := 0; i < 512; i++ {
		api.AssertIsEqual(res[i], circuit.out[i])
	}
	return nil
}

func TestSha512(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := OnCurveTest[Ed25519, Ed25519Scalars]{}
	witness := OnCurveTest[Ed25519, Ed25519Scalars]{
		P: AffinePoint[Ed25519]{
			X: emulated.NewElement[Ed25519](newBigInt("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A")),
			Y: emulated.NewElement[Ed25519](newBigInt("6666666666666666666666666666666666666666666666666666666666666658")),
		},
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

var testCurve = ecc.BN254
