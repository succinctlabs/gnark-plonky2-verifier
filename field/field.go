package field

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type EmulatedField = emulated.Goldilocks
type FTarget = emulated.Element[EmulatedField]
type Hash = [4]*FTarget

var TEST_CURVE = ecc.BN254

func NewFieldAPI(api frontend.API) *emulated.Field[emulated.Goldilocks] {
	fieldAPI, err := emulated.NewField[EmulatedField](api)
	if err != nil {
		panic(err)
	}
	return fieldAPI
}

func NewFieldConst(x uint64) *FTarget {
	val := emulated.ValueOf[EmulatedField](x)
	return &val
}

func NewFieldConstFromString(x string) *FTarget {
	val := emulated.ValueOf[EmulatedField](x)
	return &val
}

func NewFieldTarget() *FTarget {
	var field emulated.Element[emulated.Goldilocks]
	return &field
}

var ONE_F = NewFieldConst(1)
var ZERO_F = NewFieldConst(0)

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

func IsZero(api frontend.API, fieldAPI *emulated.Field[emulated.Goldilocks], x *FTarget) frontend.Variable {
	reduced := fieldAPI.Reduce(x)
	limbs := reduced.Limbs

	isZero := api.IsZero(limbs[0])
	for i := 1; i < len(limbs); i++ {
		isZero = api.Mul(isZero, api.IsZero(limbs[i]))
	}

	return isZero

}

func Println(api frontend.API, fieldAPI *emulated.Field[emulated.Goldilocks], x *FTarget) {
	reduced := fieldAPI.Reduce(x)
	limbs := reduced.Limbs
	for i := 0; i < len(limbs); i++ {
		api.Println(limbs[i])
	}
}
