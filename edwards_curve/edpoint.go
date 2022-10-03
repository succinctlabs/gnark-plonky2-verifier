package edwards_curve

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func New[T, S emulated.FieldParams](api frontend.API) (*Curve[T, S], error) {
	var t T
	var s S
	var gxb, gyb *big.Int
	var A, D *big.Int
	_, is_25519_t := any(t).(Ed25519)
	_, is_25519_s := any(s).(Ed25519Scalars)
	if is_25519_t && is_25519_s {
		// https://neuromancer.sk/std/other/Ed25519
		gxb = newBigInt("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A")
		gyb = newBigInt("6666666666666666666666666666666666666666666666666666666666666658")
		A = newBigInt("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec")
		D = newBigInt("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3")
	} else {
		return nil, fmt.Errorf("unknown curve")
	}
	return newCurve[T, S](
		api,
		emulated.NewElement[T](A),
		emulated.NewElement[T](D),
		emulated.NewElement[T](gxb),
		emulated.NewElement[T](gyb))
}

func newBigInt(s string) *big.Int {
	result, success := new(big.Int).SetString(s, 16)
	if !success {
		panic("invalid bigint")
	}
	return result
}

// TODO: could also have a type constraint for curve parameters (fields,
// equation and generator). But for now we don't do arbitrary curves.

type Curve[T, S emulated.FieldParams] struct {
	A emulated.Element[T]
	D emulated.Element[T]

	// api is the native api, we construct it ourselves to be sure
	api frontend.API
	// baseApi is the api for point operations
	baseApi frontend.API
	// scalarApi is the api for scalar operations
	scalarApi frontend.API

	g AffinePoint[T]
}

func (c *Curve[T, S]) Generator() AffinePoint[T] {
	return c.g
}

func newCurve[T, S emulated.FieldParams](api frontend.API, A, D, Gx, Gy emulated.Element[T]) (*Curve[T, S], error) {
	ba, err := emulated.NewField[T](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	sa, err := emulated.NewField[S](api)
	if err != nil {
		return nil, fmt.Errorf("new scalar api: %w", err)
	}
	return &Curve[T, S]{
		A: A,
		D: D,
		api:       api,
		baseApi:   ba,
		scalarApi: sa,
		g: AffinePoint[T]{
			X: Gx,
			Y: Gy,
		},
	}, nil
}

type AffinePoint[T emulated.FieldParams] struct {
	X, Y emulated.Element[T]
}

func (c *Curve[T, S]) Neg(p AffinePoint[T]) AffinePoint[T] {
	return AffinePoint[T]{
		X: p.X,
		Y: c.baseApi.Neg(p.Y).(emulated.Element[T]),
	}
}

func (c *Curve[T, S]) AssertIsEqual(p, q AffinePoint[T]) {
	c.baseApi.AssertIsEqual(p.X, q.X)
	c.baseApi.AssertIsEqual(p.Y, q.Y)
}

func (c *Curve[T, S]) AssertIsOnCurve(p AffinePoint[T]) {
	xx := c.baseApi.Mul(p.X, p.X)
	yy := c.baseApi.Mul(p.Y, p.Y)
	fmt.Println(xx)
	fmt.Println(c.A)
	axx := c.baseApi.Mul(xx, c.A)
	lhs := c.baseApi.Add(axx, yy)

	dxx := c.baseApi.Mul(xx, c.D)
	dxxyy := c.baseApi.Mul(dxx, yy)
	rhs := c.baseApi.Add(dxxyy, 1)

	c.baseApi.AssertIsEqual(lhs, rhs)
}

// func (c *Curve[T, S]) Add(q, r AffinePoint[T]) AffinePoint[T] {
// 	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
// 	lambda := c.baseApi.DivUnchecked(c.baseApi.Sub(r.Y, q.Y), c.baseApi.Sub(r.X, q.X))

// 	// xr = lambda**2-p.x-p1.x
// 	xr := c.baseApi.Sub(c.baseApi.Mul(lambda, lambda), c.baseApi.Add(q.X, r.X))

// 	// p.y = lambda(p.x-xr) - p.y
// 	py := c.baseApi.Sub(c.baseApi.Mul(lambda, c.baseApi.Sub(q.X, xr)), q.Y)

// 	return AffinePoint[T]{
// 		X: xr.(emulated.Element[T]),
// 		Y: py.(emulated.Element[T]),
// 	}
// }

// func (c *Curve[T, S]) Double(p AffinePoint[T]) AffinePoint[T] {

// 	// compute lambda = (3*p1.x**2+a)/2*p1.y, here we assume a=0 (j invariant 0 curve)
// 	lambda := c.baseApi.DivUnchecked(c.baseApi.Mul(p.X, p.X, 3), c.baseApi.Mul(p.Y, 2))

// 	// xr = lambda**2-p1.x-p1.x
// 	xr := c.baseApi.Sub(c.baseApi.Mul(lambda, lambda), c.baseApi.Mul(p.X, 2))

// 	// p.y = lambda(p.x-xr) - p.y
// 	py := c.baseApi.Sub(c.baseApi.Mul(lambda, c.baseApi.Sub(p.X, xr)), p.Y)

// 	return AffinePoint[T]{
// 		X: xr.(emulated.Element[T]),
// 		Y: py.(emulated.Element[T]),
// 	}
// }

func (c *Curve[T, S]) Select(b frontend.Variable, p, q AffinePoint[T]) AffinePoint[T] {
	x := c.baseApi.Select(b, p.X, q.X)
	y := c.baseApi.Select(b, p.Y, q.Y)
	return AffinePoint[T]{
		X: x.(emulated.Element[T]),
		Y: y.(emulated.Element[T]),
	}
}

// func (c *Curve[T, S]) ScalarMul(p AffinePoint[T], s emulated.Element[S]) AffinePoint[T] {
// 	res := p
// 	acc := c.Double(p)

// 	sBits := c.scalarApi.ToBinary(s)
// 	for i := 1; i < len(sBits); i++ {
// 		tmp := c.Add(res, acc)
// 		res = c.Select(sBits[i], tmp, res)
// 		acc = c.Double(acc)
// 	}

// 	tmp := c.Add(res, c.Neg(p))
// 	res = c.Select(sBits[0], res, tmp)
// 	return res
// }
