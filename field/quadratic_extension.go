package field

import (
	"fmt"
	"math/bits"

	"github.com/consensys/gnark/frontend"
)

type QETarget struct {
	Degree_zero_val FTarget
	Degree_one_val  FTarget
}

func NewQuadraticExtensionConst(Degree_zero_val *FTarget, Degree_one_val *FTarget) QETarget {
	return QETarget{*Degree_zero_val, *Degree_one_val}
}

func NewQuadraticExtensionTarget(Degree_zero_val *FTarget, Degree_one_val *FTarget) *QETarget {
	return &QETarget{*Degree_zero_val, *Degree_one_val}
}

type QuadraticExtensionAPI struct {
	api      frontend.API
	fieldAPI FieldAPI

	W        *FTarget
	DTH_ROOT *FTarget

	ONE_QE  *QETarget
	ZERO_QE *QETarget
}

func NewQuadraticExtensionAPI(api frontend.API, fieldAPI FieldAPI, degreeBits uint64) *QuadraticExtensionAPI {
	// TODO:  Should degreeBits be verified that it fits within the field and that degree is within uint64?
	return &QuadraticExtensionAPI{
		api:      api,
		fieldAPI: fieldAPI,

		W:        NewFieldConst(7),
		DTH_ROOT: NewFieldConst(18446744069414584320),

		ONE_QE:  NewQuadraticExtensionTarget(ONE_F, ZERO_F),
		ZERO_QE: NewQuadraticExtensionTarget(ZERO_F, ZERO_F),
	}
}

func (c *QuadraticExtensionAPI) SquareExtension(a *QETarget) *QETarget {
	return c.MulExtension(a, a)
}

func (c *QuadraticExtensionAPI) MulExtension(a *QETarget, b *QETarget) *QETarget {
	c_0 := c.fieldAPI.Add(c.fieldAPI.Mul(&a.Degree_zero_val, &b.Degree_zero_val), c.fieldAPI.Mul(c.W, c.fieldAPI.Mul(&a.Degree_one_val, &b.Degree_one_val)))
	c_1 := c.fieldAPI.Add(c.fieldAPI.Mul(&a.Degree_zero_val, &b.Degree_one_val), c.fieldAPI.Mul(&a.Degree_one_val, &b.Degree_zero_val))
	return NewQuadraticExtensionTarget(c_0, c_1)
}

func (c *QuadraticExtensionAPI) AddExtension(a *QETarget, b *QETarget) *QETarget {
	c_0 := c.fieldAPI.Add(&a.Degree_zero_val, &b.Degree_zero_val)
	c_1 := c.fieldAPI.Add(&a.Degree_one_val, &b.Degree_one_val)
	return NewQuadraticExtensionTarget(c_0, c_1)
}

func (c *QuadraticExtensionAPI) SubExtension(a *QETarget, b *QETarget) *QETarget {
	c_0 := c.fieldAPI.Sub(&a.Degree_zero_val, &b.Degree_zero_val)
	c_1 := c.fieldAPI.Sub(&a.Degree_one_val, &b.Degree_one_val)
	return NewQuadraticExtensionTarget(c_0, c_1)
}

func (c *QuadraticExtensionAPI) DivExtension(a *QETarget, b *QETarget) *QETarget {
	inv_b := c.InverseExtension(b)
	return c.MulExtension(a, inv_b)
}

func (c *QuadraticExtensionAPI) IsZero(a *QETarget) frontend.Variable {
	return c.api.Mul(
		IsZero(c.api, c.fieldAPI, &a.Degree_zero_val),
		IsZero(c.api, c.fieldAPI, &a.Degree_one_val),
	)
}

// TODO: Instead of calculating the inverse within the circuit, can witness the
// inverse and assert that a_inverse * a = 1.  Should reduce # of constraints.
func (c *QuadraticExtensionAPI) InverseExtension(a *QETarget) *QETarget {
	// First assert that a doesn't have 0 value coefficients

	// assert that a0_is_zero OR a1_is_zero == false
	a0_is_zero := IsZero(c.api, c.fieldAPI, &a.Degree_zero_val)
	a1_is_zero := IsZero(c.api, c.fieldAPI, &a.Degree_one_val)
	c.api.AssertIsEqual(c.api.Mul(a0_is_zero, a1_is_zero), frontend.Variable(0))

	a_pow_r_minus_1 := NewQuadraticExtensionTarget(&a.Degree_zero_val, c.fieldAPI.Mul(&a.Degree_one_val, c.DTH_ROOT))
	a_pow_r := c.MulExtension(a_pow_r_minus_1, a)
	return c.ScalarMulExtension(a_pow_r_minus_1, c.fieldAPI.Inverse(&a_pow_r.Degree_zero_val))
}

func (c *QuadraticExtensionAPI) ScalarMulExtension(a *QETarget, scalar *FTarget) *QETarget {
	return NewQuadraticExtensionTarget(c.fieldAPI.Mul(&a.Degree_zero_val, scalar), c.fieldAPI.Mul(&a.Degree_one_val, scalar))
}

func (c *QuadraticExtensionAPI) FieldToQE(a *FTarget) *QETarget {
	return NewQuadraticExtensionTarget(a, ZERO_F)
}

// / Exponentiate `base` to the power of a known `exponent`.
func (c *QuadraticExtensionAPI) ExpU64Extension(a *QETarget, exponent uint64) *QETarget {
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

func (c *QuadraticExtensionAPI) ReduceWithPowers(terms []*QETarget, scalar *QETarget) *QETarget {
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

func (c *QuadraticExtensionAPI) Select(b0 frontend.Variable, qe0, qe1 *QETarget) *QETarget {
	Degree_zero_val := c.fieldAPI.Select(b0, &qe0.Degree_zero_val, &qe1.Degree_zero_val)
	Degree_one_val := c.fieldAPI.Select(b0, &qe0.Degree_one_val, &qe1.Degree_one_val)
	return NewQuadraticExtensionTarget(Degree_zero_val, Degree_one_val)
}

func (c *QuadraticExtensionAPI) Lookup2(b0 frontend.Variable, b1 frontend.Variable, qe0, qe1, qe2, qe3 *QETarget) *QETarget {
	Degree_zero_val := c.fieldAPI.Lookup2(b0, b1, &qe0.Degree_zero_val, &qe1.Degree_zero_val, &qe2.Degree_zero_val, &qe3.Degree_zero_val)
	Degree_one_val := c.fieldAPI.Lookup2(b0, b1, &qe0.Degree_one_val, &qe1.Degree_one_val, &qe2.Degree_one_val, &qe3.Degree_one_val)
	return NewQuadraticExtensionTarget(Degree_zero_val, Degree_one_val)
}

func (c *QuadraticExtensionAPI) AssertIsEqual(a, b *QETarget) {
	c.fieldAPI.AssertIsEqual(&a.Degree_zero_val, &b.Degree_zero_val)
	c.fieldAPI.AssertIsEqual(&a.Degree_one_val, &b.Degree_one_val)
}

func (c *QuadraticExtensionAPI) Println(a *QETarget) {
	fmt.Print("Degree 0 coefficient")
	Println(c.api, c.fieldAPI, &a.Degree_zero_val)

	fmt.Print("Degree 1 coefficient")
	Println(c.api, c.fieldAPI, &a.Degree_one_val)
}
