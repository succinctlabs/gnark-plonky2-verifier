package field

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

type EmulatedField = emulated.Goldilocks
type F = *emulated.Element[EmulatedField]
type FieldAPI = *emulated.Field[emulated.Goldilocks]

var TEST_CURVE = ecc.BN254

func NewFieldAPI(api frontend.API) FieldAPI {
	fieldAPI, err := emulated.NewField[EmulatedField](api)
	if err != nil {
		panic(err)
	}
	return fieldAPI
}

func NewFieldConst(x uint64) F {
	val := emulated.ValueOf[EmulatedField](x)
	return &val
}

func NewFieldConstFromString(x string) F {
	val := emulated.ValueOf[EmulatedField](x)
	return &val
}

var ONE_F = NewFieldConst(1)
var ZERO_F = NewFieldConst(0)
var NEG_ONE_F = NewFieldConst(EmulatedField{}.Modulus().Uint64() - 1)

var GOLDILOCKS_MULTIPLICATIVE_GROUP_GENERATOR = goldilocks.NewElement(7)
var GOLDILOCKS_TWO_ADICITY = uint64(32)
var GOLDILOCKS_POWER_OF_TWO_GENERATOR = goldilocks.NewElement(1753635133440165772)
var GOLDILOCKS_MODULUS = EmulatedField{}.Modulus()

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

func IsZero(api frontend.API, fieldAPI *emulated.Field[emulated.Goldilocks], x F) frontend.Variable {
	reduced := fieldAPI.Reduce(x)
	limbs := reduced.Limbs

	isZero := api.IsZero(limbs[0])
	for i := 1; i < len(limbs); i++ {
		isZero = api.Mul(isZero, api.IsZero(limbs[i]))
	}

	return isZero

}

func init() {
	// register hints
	hint.Register(GoldilocksMulAddHint)
}

func GoldilocksRangeCheck(api frontend.API, x frontend.Variable) {
	// Goldilocks' modulus is "1111111111111111111111111111111100000000000000000000000000000001' in big endian binary
	// We check that if the 32nd to 63rd bits are all 1, then the 0th to 31st bits are all zero

	// First decompose x into 64 bits.
	bits, err := api.Compiler().NewHint(bits.NBits, 64, x)
	if err != nil {
		panic(err)
	}

	// All the remaining bits should compose back to x
	reconstructedX := frontend.Variable(0)
	c := uint64(1)
	for i := 0; i < 64; i++ {
		reconstructedX = api.Add(reconstructedX, api.Mul(bits[i], c))
		c = c << 1
		api.AssertIsBoolean(bits[i])
	}
	api.AssertIsEqual(x, reconstructedX)

	mostSigBits32Sum := frontend.Variable(0)
	for i := 32; i < 64; i++ {
		mostSigBits32Sum = api.Add(mostSigBits32Sum, bits[i])
	}

	leastSigBits32Sum := frontend.Variable(0)
	for i := 0; i < 32; i++ {
		leastSigBits32Sum = api.Add(leastSigBits32Sum, bits[i])
	}

	// If mostSigBits32Sum == 32, then check that the least significant 32 bits are all zero
	shouldCheck := api.IsZero(api.Sub(mostSigBits32Sum, 32))
	api.AssertIsEqual(
		api.Select(
			shouldCheck,
			leastSigBits32Sum,
			frontend.Variable(0),
		),
		frontend.Variable(0),
	)
}

// Calculates operands[0] * operands[1] + operands[2]
// This function assumes that all operands are within goldilocks, and will panic otherwise
// It will ensure that the result is within goldilocks
func GoldilocksMulAdd(api frontend.API, operand1, operand2, operand3 frontend.Variable) frontend.Variable {
	result, err := api.Compiler().NewHint(GoldilocksMulAddHint, 2, operand1, operand2, operand3)
	if err != nil {
		panic(err)
	}

	quotient := result[0]
	remainder := result[1]

	// Verify the calculated value
	lhs := api.Mul(operand1, operand2)
	lhs = api.Add(lhs, operand3)
	rhs := api.Add(api.Mul(quotient, GOLDILOCKS_MODULUS), remainder)
	api.AssertIsEqual(lhs, rhs)

	GoldilocksRangeCheck(api, quotient)
	GoldilocksRangeCheck(api, remainder)

	return remainder
}

func GoldilocksMulAddHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) < 3 {
		return fmt.Errorf("GoldilocksMulAddHint expects at least 3 inputs")
	}

	for _, operand := range inputs {
		if operand.Cmp(GOLDILOCKS_MODULUS) >= 0 {
			return fmt.Errorf("%s is not in the field", operand.String())
		}
	}

	product := big.NewInt(1)
	for i := 0; i < len(inputs)-1; i++ {
		product = new(big.Int).Mul(product, inputs[i])
	}

	sum := new(big.Int).Add(product, inputs[len(inputs)-1])
	quotient := new(big.Int).Div(sum, GOLDILOCKS_MODULUS)
	remainder := new(big.Int).Rem(sum, GOLDILOCKS_MODULUS)

	results[0] = quotient
	results[1] = remainder

	return nil
}

func GoldilocksReduce(api frontend.API, x frontend.Variable) frontend.Variable {
	// Use gnark's emulated field library.
	fieldAPI := NewFieldAPI(api)
	element := fieldAPI.NewElement(x)
	return fieldAPI.Reduce(element).Limbs[0]
}
