package field

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type EmulatedField = emulated.Goldilocks
type F = emulated.Element[EmulatedField]
type QuadraticExtension = [2]F
type Hash = [4]F

var TEST_CURVE = ecc.BN254

func NewFieldElement(x uint64) F {
	return emulated.NewElement[EmulatedField](x)
}

func NewFieldElementFromString(x string) F {
	return emulated.NewElement[EmulatedField](x)
}

func NewFieldAPI(api frontend.API) frontend.API {
	field, err := emulated.NewField[EmulatedField](api)
	if err != nil {
		panic(err)
	}
	return field
}
