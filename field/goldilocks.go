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
type F_DEREF = emulated.Element[EmulatedField]
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
var NEG_ONE_VAR = frontend.Variable(EmulatedField{}.Modulus().Uint64() - 1)
var GOLDILOCKS_MODULUS = EmulatedField{}.Modulus()

var ZERO_VAR = frontend.Variable(0)
var ONE_VAR = frontend.Variable(1)

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
	hint.Register(GoldilocksReduceHint)
}

func QuotientRangeCheck(api frontend.API, x frontend.Variable) {
	// Assuming that BN254 is the underlying curve, then the quotient
	// is in the range [0, 1186564023953193351969894564072376490961964393355920015360]
	// Big endian binary representation (190 digits) is
	// 11000001100100010011100111001100010001100101011110111000000000000000000000000000000
	// 00000000000000000000000000000000000000000000000000000000000000000000000000000000000
	// 000000000000000000000000
	//
	// This function will verify all the 190+ bits are 0
	// Will break up the bit representation into chunks where each chunk is a sequence of
	// contiguous 1 or 0.

	// First decompose x into bits.
	if api.Compiler().Field().Cmp(ecc.BN254.ScalarField()) != 0 {
		panic("This function only works for BN254")
	}

	maxBitLen := api.Compiler().FieldBitLen()

	bits, err := api.Compiler().NewHint(bits.NBits, maxBitLen, x)
	if err != nil {
		panic(err)
	}

	// All bits that are >= 190 should be zero
	bitAccumulator := ZERO_VAR
	for i := 190; i < len(bits); i++ {
		bitAccumulator = api.Add(bitAccumulator, bits[i])
	}
	api.IsZero(bitAccumulator)

	// All the remaining bits should compose back to x
	reconstructedX := ZERO_VAR
	c := big.NewInt(1)
	for i := 0; i < 190; i++ {
		reconstructedX = api.Add(reconstructedX, api.Mul(bits[i], c))
		c = c.Lsh(c, 1)
		api.AssertIsBoolean(bits[i])
	}
	api.AssertIsEqual(x, reconstructedX)

	// Break up the bit representation into chunks where each chunk is a sequence of
	// contiguous 1 or 0.
	chunks := [][]int{
		{137, 138, 139},
		{140},
		{141, 142, 143, 144},
		{145},
		{146},
		{147},
		{148},
		{149, 150},
		{151, 152},
		{153, 154, 155},
		{156},
		{157, 158, 159},
		{160, 161},
		{162, 163},
		{164, 165, 166},
		{167, 168},
		{169, 170, 171},
		{172, 173},
		{174},
		{175, 176, 177},
		{178},
		{179, 180},
		{181, 182},
		{183, 184, 185, 186, 187},
		{188, 189},
	}

	chunkOnes := []bool{
		true,
		false,
		true,
		false,
		true,
		false,
		true,
		false,
		true,
		false,
		true,
		false,
		true,
		false,
		true,
		false,
		true,
		false,
		true,
		false,
		true,
		false,
		true,
		false,
		true,
	}

	lastChunkCheck := ZERO_VAR
	for i := 0; i < 137; i++ {
		lastChunkCheck = api.Add(lastChunkCheck, bits[i])
	}

	previousChunkCheck := api.Sub(api.IsZero(lastChunkCheck), ONE_VAR)
	for i := 0; i < len(chunks); i++ {
		chunkSum := ZERO_VAR
		for j := 0; j < len(chunks[i]); j++ {
			chunkSum = api.Add(chunkSum, bits[chunks[i][j]])
		}

		if chunkOnes[i] {
			// Check if all the bits are 1s
			shouldCheckPrevChunk := api.IsZero(api.Sub(chunkSum, uint64(len(chunks[i]))))
			previousChunkCheck = api.Select(shouldCheckPrevChunk, previousChunkCheck, ZERO_VAR)
		} else {
			// Check if all the bits are 0s
			shouldCheckPrevChunk := api.IsZero(chunkSum)
			previousChunkCheck = api.Select(shouldCheckPrevChunk, previousChunkCheck, ONE_VAR)
		}

	}

	api.AssertIsEqual(previousChunkCheck, ZERO_VAR)
}

func GoldilocksRangeCheck(api frontend.API, x frontend.Variable) {
	// Goldilocks' modulus is "1111111111111111111111111111111100000000000000000000000000000001' in big endian binary
	// We first check that all of the 64+ bits are zero
	// We then check that if the 32rd bit to 63th bit are all 1, then the 0th bit to the 31st bit are all zero

	// First decompose x into bits.
	maxBitLen := api.Compiler().FieldBitLen()

	bits, err := api.Compiler().NewHint(bits.NBits, maxBitLen, x)
	if err != nil {
		panic(err)
	}

	// All bits that are >= 64 should be zero
	bitAccumulator := ZERO_VAR
	for i := 64; i < len(bits); i++ {
		bitAccumulator = api.Add(bitAccumulator, bits[i])
	}
	api.IsZero(bitAccumulator)

	// All the remaining bits should compose back to x
	reconstructedX := ZERO_VAR
	c := uint64(1)
	for i := 0; i < 64; i++ {
		reconstructedX = api.Add(reconstructedX, api.Mul(bits[i], c))
		c = c << 1
		api.AssertIsBoolean(bits[i])
	}
	api.AssertIsEqual(x, reconstructedX)

	mostSigBits32Sum := ZERO_VAR
	for i := 32; i < 64; i++ {
		mostSigBits32Sum = api.Add(mostSigBits32Sum, bits[i])
	}

	leastSigBits32Sum := ZERO_VAR
	for i := 0; i < 32; i++ {
		leastSigBits32Sum = api.Add(leastSigBits32Sum, bits[i])
	}

	// If mostSigBits32Sum == 32, then check that the least significant 32 bits are all zero
	shouldCheck := api.IsZero(api.Sub(mostSigBits32Sum, 32))
	api.AssertIsEqual(
		api.Select(
			shouldCheck,
			leastSigBits32Sum,
			ZERO_VAR,
		),
		ZERO_VAR,
	)
}

// Calculates product(operands[0:len(operands)-1]) + operands[len(operands)-1]
// This function assumes that all operands are within goldilocks, and will panic otherwise
func GoldilocksMulAdd(api frontend.API, operands ...frontend.Variable) frontend.Variable {
	if len(operands) < 3 || len(operands) > 4 {
		panic("GoldilocksMulAdd expects at 3 or 4 operands")
	}

	result, err := api.Compiler().NewHint(GoldilocksMulAddHint, 2, operands...)
	if err != nil {
		panic(err)
	}

	quotient := result[0]
	remainder := result[1]

	// Verify the calculated value
	lhs := frontend.Variable(1)
	for i := 0; i < len(operands)-1; i++ {
		lhs = api.Mul(lhs, operands[i])
	}

	lhs = api.Add(lhs, operands[len(operands)-1])
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
	mulResults, err := api.Compiler().NewHint(GoldilocksReduceHint, 2, x)
	if err != nil {
		panic(err)
	}
	quotient := mulResults[0]
	remainder := mulResults[1]

	// Verify that x == quotient * modulus + remainder
	rhs := api.Add(api.Mul(quotient, GOLDILOCKS_MODULUS), remainder)
	api.AssertIsEqual(x, rhs)

	QuotientRangeCheck(api, quotient)
	GoldilocksRangeCheck(api, remainder)

	return remainder
}

func GoldilocksReduceHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("GoldilocksReduceHint expects 1 input")
	}

	x := inputs[0]

	goldilocksModulus := EmulatedField{}.Modulus()
	quotient := new(big.Int).Div(x, goldilocksModulus)
	remainder := new(big.Int).Rem(x, goldilocksModulus)

	results[0] = quotient
	results[1] = remainder

	return nil
}
