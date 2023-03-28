package plonky2_verifier

import (
	"fmt"
	. "gnark-plonky2-verifier/field"
	"math/bits"

	"github.com/consensys/gnark/frontend"
)

type QuadraticExtensionAPI struct {
	fieldAPI frontend.API

	W        F
	DTH_ROOT F

	ONE_QE  QuadraticExtension
	ZERO_QE QuadraticExtension
}

func NewQuadraticExtensionAPI(fieldAPI frontend.API, degreeBits uint64) *QuadraticExtensionAPI {
	// TODO:  Should degreeBits be verified that it fits within the field and that degree is within uint64?

	return &QuadraticExtensionAPI{
		fieldAPI: fieldAPI,

		W:        NewFieldElement(7),
		DTH_ROOT: NewFieldElement(18446744069414584320),

		ONE_QE:  QuadraticExtension{ONE_F, ZERO_F},
		ZERO_QE: QuadraticExtension{ZERO_F, ZERO_F},
	}
}

func (c *QuadraticExtensionAPI) SquareExtension(a QuadraticExtension) QuadraticExtension {
	return c.MulExtension(a, a)
}

func (c *QuadraticExtensionAPI) MulExtension(a QuadraticExtension, b QuadraticExtension) QuadraticExtension {
	c_0 := c.fieldAPI.Add(c.fieldAPI.Mul(a[0], b[0]).(F), c.fieldAPI.Mul(c.W, a[1], b[1])).(F)
	c_1 := c.fieldAPI.Add(c.fieldAPI.Mul(a[0], b[1]).(F), c.fieldAPI.Mul(a[1], b[0])).(F)
	return QuadraticExtension{c_0, c_1}
}

func (c *QuadraticExtensionAPI) AddExtension(a QuadraticExtension, b QuadraticExtension) QuadraticExtension {
	c_0 := c.fieldAPI.Add(a[0], b[0]).(F)
	c_1 := c.fieldAPI.Add(a[1], b[1]).(F)
	return QuadraticExtension{c_0, c_1}
}

func (c *QuadraticExtensionAPI) SubExtension(a QuadraticExtension, b QuadraticExtension) QuadraticExtension {
	c_0 := c.fieldAPI.Sub(a[0], b[0]).(F)
	c_1 := c.fieldAPI.Sub(a[1], b[1]).(F)
	return QuadraticExtension{c_0, c_1}
}

func (c *QuadraticExtensionAPI) DivExtension(a QuadraticExtension, b QuadraticExtension) QuadraticExtension {
	return c.MulExtension(a, c.InverseExtension(b))
}

func (c *QuadraticExtensionAPI) IsZero(a QuadraticExtension) frontend.Variable {
	return c.fieldAPI.Mul(c.fieldAPI.IsZero(a[0]), c.fieldAPI.IsZero(a[1]))
}

// TODO: Instead of calculating the inverse within the circuit, can witness the
// inverse and assert that a_inverse * a = 1.  Should reduce # of constraints.
func (c *QuadraticExtensionAPI) InverseExtension(a QuadraticExtension) QuadraticExtension {
	// First assert that a doesn't have 0 value coefficients
	a0_is_zero := c.fieldAPI.IsZero(a[0])
	a1_is_zero := c.fieldAPI.IsZero(a[1])

	// assert that a0_is_zero OR a1_is_zero == false
	c.fieldAPI.AssertIsEqual(c.fieldAPI.Mul(a0_is_zero, a1_is_zero).(F), ZERO_F)

	a_pow_r_minus_1 := QuadraticExtension{a[0], c.fieldAPI.Mul(a[1], c.DTH_ROOT).(F)}
	a_pow_r := c.MulExtension(a_pow_r_minus_1, a)
	return c.ScalarMulExtension(a_pow_r_minus_1, c.fieldAPI.Inverse(a_pow_r[0]).(F))
}

func (c *QuadraticExtensionAPI) ScalarMulExtension(a QuadraticExtension, scalar F) QuadraticExtension {
	return QuadraticExtension{c.fieldAPI.Mul(a[0], scalar).(F), c.fieldAPI.Mul(a[1], scalar).(F)}
}

func (c *QuadraticExtensionAPI) FieldToQE(a F) QuadraticExtension {
	return QuadraticExtension{a, ZERO_F}
}

// / Exponentiate `base` to the power of a known `exponent`.
func (c *QuadraticExtensionAPI) ExpU64Extension(a QuadraticExtension, exponent uint64) QuadraticExtension {
	switch exponent {
	case 0:
		return c.ONE_QE
	case 1:
		return a
	case 2:
		return c.SquareExtension(a)
	default:
	}

	current := a
	product := c.ONE_QE

	for i := 0; i < bits.Len64(exponent); i++ {
		if i != 0 {
			current = c.SquareExtension(current)
		}

		if (exponent >> i & 1) != 0 {
			product = c.MulExtension(product, current)
		}
	}

	return product
}

func (c *QuadraticExtensionAPI) ReduceWithPowers(terms []QuadraticExtension, scalar QuadraticExtension) QuadraticExtension {
	sum := c.ZERO_QE

	for i := len(terms) - 1; i >= 0; i-- {
		sum = c.AddExtension(
			c.MulExtension(
				sum,
				scalar,
			),
			terms[i],
		)
	}

	return sum
}

func (c *QuadraticExtensionAPI) Select(b0 frontend.Variable, qe0, qe1 QuadraticExtension) QuadraticExtension {
	var retQE QuadraticExtension

	for i := 0; i < 2; i++ {
		retQE[i] = c.fieldAPI.Select(b0, qe0[i], qe1[i]).(F)
	}

	return retQE
}

func (c *QuadraticExtensionAPI) Lookup2(b0 frontend.Variable, b1 frontend.Variable, qe0, qe1, qe2, qe3 QuadraticExtension) QuadraticExtension {
	var retQE QuadraticExtension

	for i := 0; i < 2; i++ {
		retQE[i] = c.fieldAPI.Lookup2(b0, b1, qe0[i], qe1[i], qe2[i], qe3[i]).(F)
	}

	return retQE
}

func (c *QuadraticExtensionAPI) AssertIsEqual(a, b QuadraticExtension) {
	for i := 0; i < 2; i++ {
		c.fieldAPI.AssertIsEqual(a[0], b[0])
	}
}

func (c *QuadraticExtensionAPI) Println(a QuadraticExtension) {
	fmt.Print("Degree 0 coefficient")
	c.fieldAPI.Println(a[0])

	fmt.Print("Degree 1 coefficient")
	c.fieldAPI.Println(a[1])
}
