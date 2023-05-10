package field

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type EmulatedField = emulated.Goldilocks
type F = *emulated.Element[EmulatedField]
type Hash = [4]F
type EmulatedFieldAPI struct {
	api      frontend.API
	fieldAPI *emulated.Field[EmulatedField]
}

var TEST_CURVE = ecc.BN254

func NewFieldElement(x uint64) F {
	constField := emulated.ValueOf[EmulatedField](x)
	return &constField
}

func NewFieldElementFromString(x string) F {
	constField := emulated.ValueOf[EmulatedField](x)
	return &constField
}

func NewFieldAPI(api frontend.API) *EmulatedFieldAPI {
	fieldAPI, err := emulated.NewField[EmulatedField](api)
	if err != nil {
		panic(err)
	}
	return &EmulatedFieldAPI{api, fieldAPI}
}

var ONE_F = NewFieldElement(1)
var ZERO_F = NewFieldElement(0)

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

func (e EmulatedFieldAPI) IsZero(x F) frontend.Variable {
	reduced := e.fieldAPI.Reduce(x)
	limbs := reduced.Limbs

	isZero := e.api.IsZero(limbs[0])
	for i := 1; i < len(limbs); i++ {
		isZero = e.api.Mul(isZero, e.api.IsZero(limbs[i]))
	}

	return isZero
}

func (e EmulatedFieldAPI) Add(a F, b F) F {
	return e.fieldAPI.Add(a, b)
}

func (e EmulatedFieldAPI) Sub(a F, b F) F {
	return e.fieldAPI.Sub(a, b)
}

func (e EmulatedFieldAPI) Mul(a F, b F) F {
	return e.fieldAPI.Mul(a, b)
}

func (e EmulatedFieldAPI) AssertIsEqual(a F, b F) {
	e.fieldAPI.AssertIsEqual(a, b)
}

func (e EmulatedFieldAPI) Inverse(x F) F {
	return e.fieldAPI.Inverse(x)
}

func (e EmulatedFieldAPI) Select(selector frontend.Variable, a F, b F) F {
	return e.fieldAPI.Select(selector, a, b)
}

func (e EmulatedFieldAPI) Lookup2(b0 frontend.Variable, b1 frontend.Variable, a F, b F, c F, d F) F {
	return e.fieldAPI.Lookup2(b0, b1, a, b, c, d)
}

func (e EmulatedFieldAPI) Println(x F) {
	reduced := e.fieldAPI.Reduce(x)
	limbs := reduced.Limbs
	for i := 0; i < len(limbs); i++ {
		e.api.Println(limbs[i])
	}
}
