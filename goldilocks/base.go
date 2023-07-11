// This package implements efficient Golidlocks arithmetic operations within Gnark. We do not use
// the emulated field arithmetic API, because it is too slow for our purposes. Instead, we use
// an efficient reduction method that leverages the fact that the modulus is a simple
// linear combination of powers of two.
package goldilocks

// In general, methods whose name do not contain `NoReduce` can be used without any extra mental
// overhead. These methods act exactly as you would expect a normal field would operate.
//
// However, if you want to aggressively optimize the number of constraints in your circuit, it can
// be very beneficial to use the no reduction methods and keep track of the maximum number of bits
// your computation uses.

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

// The multiplicative group generator of the field.
var MULTIPLICATIVE_GROUP_GENERATOR goldilocks.Element = goldilocks.NewElement(7)

// The two adicity of the field.
var TWO_ADICITY uint64 = 32

// The power of two generator of the field.
var POWER_OF_TWO_GENERATOR goldilocks.Element = goldilocks.NewElement(1753635133440165772)

// The modulus of the field.
var MODULUS *big.Int = emulated.Goldilocks{}.Modulus()

// The threshold maximum number of bits at which we must reduce the element.
var REDUCE_NB_BITS_THRESHOLD uint8 = 254 - 64

// The number of bits to use for range checks on inner products of field elements.
var RANGE_CHECK_NB_BITS int = 140

// Registers the hint functions with the solver.
func init() {
	solver.RegisterHint(MulAddHint)
	solver.RegisterHint(ReduceHint)
	solver.RegisterHint(InverseHint)
}

// A type alias used to represent Goldilocks field elements.
type Variable struct {
	Limb frontend.Variable
}

// Creates a new Goldilocks field element from an existing variable. Assumes that the element is
// already reduced.
func NewVariable(x frontend.Variable) Variable {
	return Variable{Limb: x}
}

// The zero element in the Golidlocks field.
func Zero() Variable {
	return NewVariable(0)
}

// The one element in the Goldilocks field.
func One() Variable {
	return NewVariable(1)
}

// The negative one element in the Goldilocks field.
func NegOne() Variable {
	return NewVariable(MODULUS.Uint64() - 1)
}

// The chip used for Goldilocks field operations.
type Chip struct {
	api frontend.API
}

// Creates a new Goldilocks chip.
func NewChip(api frontend.API) *Chip {
	return &Chip{api: api}
}

// Adds two field elements such that x + y = z within the Golidlocks field.
func (p *Chip) Add(a Variable, b Variable) Variable {
	return p.MulAdd(a, NewVariable(1), b)
}

// Adds two field elements such that x + y = z within the Golidlocks field without reducing.
func (p *Chip) AddNoReduce(a Variable, b Variable) Variable {
	return NewVariable(p.api.Add(a.Limb, b.Limb))
}

// Subtracts two field elements such that x + y = z within the Golidlocks field.
func (p *Chip) Sub(a Variable, b Variable) Variable {
	return p.MulAdd(b, NewVariable(MODULUS.Uint64()-1), a)
}

// Subtracts two field elements such that x + y = z within the Golidlocks field without reducing.
func (p *Chip) SubNoReduce(a Variable, b Variable) Variable {
	return NewVariable(p.api.Add(a.Limb, p.api.Mul(b.Limb, MODULUS.Uint64()-1)))
}

// Multiplies two field elements such that x * y = z within the Golidlocks field.
func (p *Chip) Mul(a Variable, b Variable) Variable {
	return p.MulAdd(a, b, Zero())
}

// Multiplies two field elements such that x * y = z within the Golidlocks field without reducing.
func (p *Chip) MulNoReduce(a Variable, b Variable) Variable {
	return NewVariable(p.api.Mul(a.Limb, b.Limb))
}

// Multiplies two field elements and adds a field element such that x * y + z = c within the
// Golidlocks field.
func (p *Chip) MulAdd(a Variable, b Variable, c Variable) Variable {
	result, err := p.api.Compiler().NewHint(MulAddHint, 2, a.Limb, b.Limb, c.Limb)
	if err != nil {
		panic(err)
	}

	quotient := NewVariable(result[0])
	remainder := NewVariable(result[1])

	lhs := p.api.Mul(a.Limb, b.Limb)
	lhs = p.api.Add(lhs, c.Limb)
	rhs := p.api.Add(p.api.Mul(quotient.Limb, MODULUS), remainder.Limb)
	p.api.AssertIsEqual(lhs, rhs)

	p.RangeCheck(quotient)
	p.RangeCheck(remainder)
	return remainder
}

// Multiplies two field elements and adds a field element such that x * y + z = c within the
// Golidlocks field without reducing.
func (p *Chip) MulAddNoReduce(a Variable, b Variable, c Variable) Variable {
	return p.AddNoReduce(p.MulNoReduce(a, b), c)
}

// The hint used to compute MulAdd.
func MulAddHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 3 {
		panic("MulAddHint expects 3 input operands")
	}

	for _, operand := range inputs {
		if operand.Cmp(MODULUS) >= 0 {
			panic(fmt.Sprintf("%s is not in the field", operand.String()))
		}
	}

	product := new(big.Int).Mul(inputs[0], inputs[1])
	sum := new(big.Int).Add(product, inputs[2])
	quotient := new(big.Int).Div(sum, MODULUS)
	remainder := new(big.Int).Rem(sum, MODULUS)

	results[0] = quotient
	results[1] = remainder

	return nil
}

// Reduces a field element x such that x % MODULUS = y.
func (p *Chip) Reduce(x Variable) Variable {
	// Witness a `quotient` and `remainder` such that:
	//
	// 		MODULUS * quotient + remainder = x
	//
	// Must check that remainder \in [0, MODULUS) and quotient \in [0, 2^RANGE_CHECK_NB_BITS) to ensure
	// that this computation does not overflow. We use 2^140 to reduce the cost of the range check
	// and because 2^RANGE_CHECK_NB_BITS * 2^64 = 2^194 < p < 2^254.

	result, err := p.api.Compiler().NewHint(ReduceHint, 2, x.Limb)
	if err != nil {
		panic(err)
	}

	quotient := result[0]
	rangeCheckNbBits := RANGE_CHECK_NB_BITS
	p.api.ToBinary(quotient, rangeCheckNbBits)

	remainder := NewVariable(result[1])
	p.RangeCheck(remainder)
	return remainder
}

// Reduces a field element x such that x % MODULUS = y.
func (p *Chip) ReduceWithMaxBits(x Variable, maxNbBits uint64) Variable {
	// Witness a `quotient` and `remainder` such that:
	//
	// 		MODULUS * quotient + remainder = x
	//
	// Must check that offset \in [0, MODULUS) and carry \in [0, 2^maxNbBits) to ensure that this
	// computation does not overflow.

	result, err := p.api.Compiler().NewHint(ReduceHint, 2, x.Limb)
	if err != nil {
		panic(err)
	}

	quotient := result[0]
	p.api.ToBinary(quotient, int(maxNbBits))

	remainder := NewVariable(result[1])
	p.RangeCheck(remainder)
	return remainder
}

// The hint used to compute Reduce.
func ReduceHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("ReduceHint expects 1 input operand")
	}
	input := inputs[0]
	quotient := new(big.Int).Div(input, MODULUS)
	remainder := new(big.Int).Rem(input, MODULUS)
	results[0] = quotient
	results[1] = remainder
	return nil
}

// Computes the inverse of a field element x such that x * x^-1 = 1.
func (p *Chip) Inverse(x Variable) Variable {
	result, err := p.api.Compiler().NewHint(InverseHint, 1, x.Limb)
	if err != nil {
		panic(err)
	}

	inverse := NewVariable(result[0])
	product := p.Mul(inverse, x)
	p.api.AssertIsEqual(product.Limb, frontend.Variable(1))
	return inverse
}

// The hint used to compute Inverse.
func InverseHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("InverseHint expects 1 input operand")
	}

	input := inputs[0]
	if input.Cmp(MODULUS) == 0 || input.Cmp(MODULUS) == 1 {
		panic("Input is not in the field")
	}

	inputGl := goldilocks.NewElement(input.Uint64())
	resultGl := goldilocks.NewElement(0)
	resultGl.Inverse(&inputGl)

	result := big.NewInt(0)
	results[0] = resultGl.BigInt(result)

	return nil
}

// Computes a field element raised to some power.
func (p *Chip) Exp(x Variable, k *big.Int) Variable {
	if k.IsUint64() && k.Uint64() == 0 {
		return One()
	}

	e := k
	if k.Sign() == -1 {
		panic("Unsupported negative exponent. Need to implement inversion.")
	}

	z := x
	for i := e.BitLen() - 2; i >= 0; i-- {
		z = p.Mul(z, z)
		if e.Bit(i) == 1 {
			z = p.Mul(z, x)
		}
	}

	return z
}

// Range checks a field element x to be less than the Golidlocks modulus 2 ^ 64 - 2 ^ 32 + 1.
func (p *Chip) RangeCheck(x Variable) {
	// The Goldilocks' modulus is 2^64 - 2^32 + 1, which is:
	//
	// 		1111111111111111111111111111111100000000000000000000000000000001
	//
	// in big endian binary. This function will first verify that x is at most 64 bits wide. Then it
	// checks that if the bits[0:31] (in big-endian) are all 1, then bits[32:64] are all zero.

	// First decompose x into 64 bits.  The bits will be in little-endian order.
	bits := bits.ToBinary(p.api, x.Limb, bits.WithNbDigits(64))

	// Those bits should compose back to x.
	reconstructedX := frontend.Variable(0)
	c := uint64(1)
	for i := 0; i < 64; i++ {
		reconstructedX = p.api.Add(reconstructedX, p.api.Mul(bits[i], c))
		c = c << 1
		p.api.AssertIsBoolean(bits[i])
	}
	p.api.AssertIsEqual(x.Limb, reconstructedX)

	mostSigBits32Sum := frontend.Variable(0)
	for i := 32; i < 64; i++ {
		mostSigBits32Sum = p.api.Add(mostSigBits32Sum, bits[i])
	}

	leastSigBits32Sum := frontend.Variable(0)
	for i := 0; i < 32; i++ {
		leastSigBits32Sum = p.api.Add(leastSigBits32Sum, bits[i])
	}

	// If mostSigBits32Sum < 32, then we know that:
	//
	// 		x < (2^63 + ... + 2^32 + 0 * 2^31 + ... + 0 * 2^0)
	//
	// which equals to 2^64 - 2^32. So in that case, we don't need to do any more checks. If
	// mostSigBits32Sum == 32, then we need to check that x == 2^64 - 2^32 (max GL value).
	shouldCheck := p.api.IsZero(p.api.Sub(mostSigBits32Sum, 32))
	p.api.AssertIsEqual(
		p.api.Select(
			shouldCheck,
			leastSigBits32Sum,
			frontend.Variable(0),
		),
		frontend.Variable(0),
	)
}

func (p *Chip) AssertIsEqual(x, y Variable) {
	p.api.AssertIsEqual(x.Limb, y.Limb)
}

// Computes the n'th primitive root of unity for the Goldilocks field.
func PrimitiveRootOfUnity(nLog uint64) goldilocks.Element {
	if nLog > TWO_ADICITY {
		panic("nLog is greater than TWO_ADICITY")
	}
	res := goldilocks.NewElement(POWER_OF_TWO_GENERATOR.Uint64())
	for i := 0; i < int(TWO_ADICITY-nLog); i++ {
		res.Square(&res)
	}
	return res
}

func TwoAdicSubgroup(nLog uint64) []goldilocks.Element {
	if nLog > TWO_ADICITY {
		panic("nLog is greater than GOLDILOCKS_TWO_ADICITY")
	}

	var res []goldilocks.Element
	rootOfUnity := PrimitiveRootOfUnity(nLog)
	res = append(res, goldilocks.NewElement(1))

	for i := 0; i < (1 << nLog); i++ {
		lastElement := res[len(res)-1]
		res = append(res, *lastElement.Mul(&lastElement, &rootOfUnity))
	}

	return res
}
