package field

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type EmulatedField = emulated.Goldilocks
type F = emulated.Element[EmulatedField]
type FieldAPI = *emulated.Field[emulated.Goldilocks]

var TEST_CURVE = ecc.BN254

func NewFieldAPI(api frontend.API) FieldAPI {
	fieldAPI, err := emulated.NewField[EmulatedField](api)
	if err != nil {
		panic(err)
	}
	return fieldAPI
}

func NewFieldConst(x uint64) *F {
	val := emulated.ValueOf[EmulatedField](x)
	return &val
}

func NewFieldConstFromString(x string) *F {
	val := emulated.ValueOf[EmulatedField](x)
	return &val
}

func NewFieldTarget() *F {
	var field emulated.Element[emulated.Goldilocks]
	return &field
}

var ONE_F = NewFieldConst(1)
var ZERO_F = NewFieldConst(0)
var NEG_ONE_F = NewFieldConst(EmulatedField{}.Modulus().Uint64() - 1)

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

func IsZero(api frontend.API, fieldAPI *emulated.Field[emulated.Goldilocks], x *F) frontend.Variable {
	reduced := fieldAPI.Reduce(x)
	limbs := reduced.Limbs

	isZero := api.IsZero(limbs[0])
	for i := 1; i < len(limbs); i++ {
		isZero = api.Mul(isZero, api.IsZero(limbs[i]))
	}

	return isZero

}
