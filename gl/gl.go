// This package implements efficient Golidlocks arithmetic operations within Gnark. We do not use
// the emulated field arithmetic API, because it is too slow for our purposes. Instead, we use
// an efficient reduction method that leverages the fact that the modulus is a simple
// linear combination of powers of two.
package gl

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
var MULTIPLICATIVE_GROUP_GENERATOR = goldilocks.NewElement(7)

// The two adicity of the field.
var TWO_ADICITY = uint64(32)

// The power of two generator of the field.
var POWER_OF_TWO_GENERATOR = goldilocks.NewElement(1753635133440165772)

// The modulus of the field.
var MODULUS = emulated.Goldilocks{}.Modulus()

// Registers the hint functions with the solver.
func init() {
	solver.RegisterHint(MulAddHint)
	solver.RegisterHint(ReduceHint)
}

// A type alias used to represent Goldilocks field elements.
type Variable struct {
	value frontend.Variable
}

// Returns the value of the Goldilocks field element.
func (e *Variable) Value() frontend.Variable {
	return e.value
}

// Creates a new Goldilocks field element from an existing variable.
func NewVariable(x frontend.Variable) Variable {
	return Variable{value: x}
}

// Creates a new Goldilocks field element from a constant.
func NewVariableFromConst(x uint64) Variable {
	return Variable{value: frontend.Variable(x)}
}

// The chip used for Goldilocks field operations.
type Chip struct {
	api      frontend.API
	fieldAPI emulated.Field[emulated.Goldilocks]
}

// Creates a new Goldilocks chip.
func NewChip(api frontend.API) *Chip {
	fieldAPI, err := emulated.NewField[emulated.Goldilocks](api)
	if err != nil {
		panic(err)
	}
	return &Chip{api: api, fieldAPI: *fieldAPI}
}

// Adds two field elements such that x + y = z within the Golidlocks field.
func (p *Chip) Add(a Variable, b Variable) Variable {
	return p.MulAdd(a, NewVariableFromConst(1), b)
}

// Multiplies two field elements such that x * y = z within the Golidlocks field.
func (p *Chip) Mul(a Variable, b Variable) Variable {
	return p.MulAdd(a, b, NewVariableFromConst(0))
}

// Multiplies two field elements and adds a field element such that x * y + z = c within the
// Golidlocks field.
func (p *Chip) MulAdd(a Variable, b Variable, c Variable) Variable {
	result, err := p.api.Compiler().NewHint(MulAddHint, 2, a.value, b.value, c.value)
	if err != nil {
		panic(err)
	}

	quotient := NewVariable(result[0])
	remainder := NewVariable(result[1])

	lhs := p.api.Mul(a.value, b.value)
	lhs = p.api.Add(lhs, c.value)
	rhs := p.api.Add(p.api.Mul(quotient.value, MODULUS), remainder.value)
	p.api.AssertIsEqual(lhs, rhs)

	p.RangeCheck(quotient)
	p.RangeCheck(remainder)
	return remainder
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
	result, err := p.api.Compiler().NewHint(ReduceHint, 1, x.value)
	if err != nil {
		panic(err)
	}
	return NewVariable(result[0])
}

// The hint used to compute Reduce.
func ReduceHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("ReduceHint expects 1 input operand")
	}
	reduced := big.NewInt(0)
	reduced.Mod(inputs[0], MODULUS)
	results[0] = reduced

	return nil
}

// Computes a field element raised to some power.
func (p *Chip) Exp(x Variable, k *big.Int) Variable {
	if k.IsUint64() && k.Uint64() == 0 {
		return NewVariableFromConst(1)
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
	bits := bits.ToBinary(p.api, x.value, bits.WithNbDigits(64))

	// Those bits should compose back to x.
	reconstructedX := frontend.Variable(0)
	c := uint64(1)
	for i := 0; i < 64; i++ {
		reconstructedX = p.api.Add(reconstructedX, p.api.Mul(bits[i], c))
		c = c << 1
		p.api.AssertIsBoolean(bits[i])
	}
	p.api.AssertIsEqual(x.value, reconstructedX)

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
