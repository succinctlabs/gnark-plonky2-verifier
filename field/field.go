package field

import (
	"fmt"
	"math/big"

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

var r EmulatedField

func EmulatedFieldModulus() *big.Int {
	return r.Modulus()
}

func PrintHash(f frontend.API, h Hash) {
	for i := 0; i < 4; i++ {
		fmt.Println("Hash Limb", i)
		f.Println(h[i])
	}
}
