package field

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

const D = 2

type EmulatedField = emulated.Goldilocks
type F = emulated.Element[EmulatedField]
type QuadraticExtension = [2]F
type QEAlgebra = [D]QuadraticExtension
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

var ONE_F = NewFieldElement(1)
var ZERO_F = NewFieldElement(0)
var NEG_ONE_F = NewFieldElement(EmulatedField{}.Modulus().Uint64() - 1)

var GOLDILOCKS_MULTIPLICATIVE_GROUP_GENERATOR = goldilocks.NewElement(7)
var GOLDILOCKS_TWO_ADICITY = uint64(32)
var GOLDILOCKS_POWER_OF_TWO_GENERATOR = goldilocks.NewElement(1753635133440165772)

func GoldilocksPrimitiveRootOfUnity(nLog uint64) goldilocks.Element {
	if nLog > GOLDILOCKS_TWO_ADICITY {
		panic("nLog is greater than GOLDILOCKS_TWO_ADICITY")
	}

	res := goldilocks.NewElement(GOLDILOCKS_POWER_OF_TWO_GENERATOR.Uint64())
	for i := 0; i < int(GOLDILOCKS_TWO_ADICITY-nLog); i++ {
		res.Square(&res)
	}

	return res
}

func TwoAdicSubgroup(nLog uint64) []goldilocks.Element {
	if nLog > GOLDILOCKS_TWO_ADICITY {
		panic("nLog is greater than GOLDILOCKS_TWO_ADICITY")
	}

	var res []goldilocks.Element
	rootOfUnity := GoldilocksPrimitiveRootOfUnity(nLog)
	res = append(res, goldilocks.NewElement(1))

	for i := 0; i < (1 << nLog); i++ {
		lastElement := res[len(res)-1]
		res = append(res, *lastElement.Mul(&lastElement, &rootOfUnity))
	}

	return res
}
