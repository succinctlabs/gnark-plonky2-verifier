package edwards_curve


// This file is little-endian

import (
	"math/big"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"gnark-ed25519/sha512"
)


func H(api frontend.API, m []frontend.Variable) []frontend.Variable {
	rawResult := sha512.Sha512(api, swapByteEndianness(m))
	sResult := swapByteEndianness(rawResult[:])
	return sResult
}

func pow2(n uint) *big.Int {
	result := big.NewInt(1)
	result.Lsh(result, n)
	return result
}

type EdCurve = Curve[Ed25519, Ed25519Scalars]
type EdPoint = AffinePoint[Ed25519]
type EdCoordinate = emulated.Element[Ed25519]
type EdScalar = emulated.Element[Ed25519Scalars]

func bits_to_scalar(c *EdCurve, s []frontend.Variable) EdCoordinate {
	if len(s) != 256 { panic("bad length") }
	elt := emulated.NewElement[Ed25519](0)
	if len(elt.Limbs) != 4 { panic("bad length") }
	i := 0
	for k := 0; k < 4; k++ {
		elt.Limbs[k] = c.api.FromBinary(s[i:i+64]...)
		i += 64
	}
	if i != len(s) { panic("bad length") }
	return elt
}

// func bits_to_clamped_scalar(c *EdCurve, input []frontend.Variable) EdScalar {
// 	if len(input) != 256 { panic("bad length") }
// 	s := make([]frontend.Variable, len(input))
// 	copy(s, input)
// 	s[0] = 0
// 	s[1] = 0
// 	s[2] = 0
// 	s[254] = 1
// 	return bits_to_scalar[Ed25519Scalars](c, s)
// }

func bits_to_element(c *EdCurve, input []frontend.Variable) EdPoint {
	// L := emulated.NewElement[Ed25519Scalars](rEd25519)
	unchecked_point := decodepoint(c, input)

	// // TODO: https://github.com/warner/python-pure25519 says this check is not necessary:
	// //
	// // > This library is conservative, and performs full subgroup-membership checks on decoded
	// // > points, which adds considerable overhead. The Curve25519/Ed25519 algorithms were
	// // > designed to not require these checks, so a careful application might be able to
	// // > improve on this slightly (Ed25519 verify down to 6.2ms, DH-finish to 3.2ms).
	// c.AssertIsZero(c.ScalarMul(unchecked_point, L))

	return unchecked_point
}

// func publickey(c *EdCurve, seed []frontend.Variable) EdPoint {
// 	if len(seed) != 32 { panic("bad length") }
// 	a := bits_to_clamped_scalar(c, H(c.api, seed)[:256])
// 	return c.ScalarMul(c.g, a)
// }

func CheckValid(c *EdCurve, s, m, pk []frontend.Variable) {
	if len(s) != 512 { panic("bad signature length") }
	if len(pk) != 256 { panic("bad public key length") }
	if len(m) % 8 != 0 { panic("bad message length") }
	R := bits_to_element(c, s[:256])
	A := bits_to_element(c, pk)
	h := H(c.api, concat(s[:256], pk, m))
	v1 := c.ScalarMulBinary(c.g, s[256:])
	v2 := c.Add(R, c.ScalarMulBinary(A, h))
	c.AssertIsEqual(v1, v2)
}

func reverse[T interface{}](arr []T) []T {
	result := make([]T, len(arr))
	for i, v := range arr {
		result[len(result)-i-1] = v
	}
	return result
}

func concat(args ...[]frontend.Variable) []frontend.Variable {
	result := []frontend.Variable{}
	for _, v := range args {
		result = append(result, v...)
	}
	return result
}

func decodepoint(c *EdCurve, unclamped []frontend.Variable) EdPoint {
	if len(unclamped) != 256 { panic("bad length") }

	s := make([]frontend.Variable, len(unclamped))
	copy(s, unclamped)
	s[255] = 0
	y := bits_to_scalar(c, s)
//     unclamped = int(binascii.hexlify(s[:32][::-1]), 16)
//     clamp = (1 << 255) - 1
//     y = unclamped & clamp # clear MSB

	x := xrecover(c, y)
//     x = xrecover(y)

	xbits := c.baseApi.ToBinary(x)
	if len(xbits) != 256 { panic("bad length") }
	mismatch := c.api.Xor(xbits[0], unclamped[255])
	x = c.baseApi.Select(mismatch, c.baseApi.Neg(x), x).(EdCoordinate)
//     if bool(x & 1) != bool(unclamped & (1<<255)): x = Q-x

	P := AffinePoint[Ed25519]{
		X: x,
		Y: y,
	}
//     P = [x,y]

	c.AssertIsOnCurve(P)
//     if not isoncurve(P): raise NotOnCurve("decoding point that is not on curve")

	return P
}

func toValue(s EdCoordinate) *big.Int {
	result := big.NewInt(0)
	placeValue := big.NewInt(1)
	for _, v := range s.Limbs {
		q := new(big.Int).Mul(placeValue, v.(*big.Int))
		result.Add(result, q)
		placeValue.Lsh(placeValue, Ed25519{}.BitsPerLimb())
	}
	return result
}

func _const(x int64) EdCoordinate {
	return emulated.NewElement[Ed25519](big.NewInt(x))
}

// Q = 2**255 - 19
// L = 2**252 + 27742317777372353535851937790883648493
// def inv(x):
//     return pow(x, Q-2, Q)
// d = -121665 * inv(121666)
// I = pow(2,(Q-1)//4,Q)

func xrecover(c *EdCurve, y EdCoordinate) EdCoordinate {	
	Q := Ed25519{}.Modulus()
	I := emulated.NewElement[Ed25519](newBigInt("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0"))

	yy := c.baseApi.Mul(y, y)
	xx := c.baseApi.Div(
		c.baseApi.Sub(yy, _const(1)),
		c.baseApi.Add(c.baseApi.Mul(c.d, yy), _const(1)),
	).(EdCoordinate)
	// xx = (y*y-1) * inv(d*y*y+1)

	power := new(big.Int).Add(Q, big.NewInt(3))
	power.Rsh(power, 3)
	x := pow(c, xx, power)
	// x = pow(xx,(Q+3)//8,Q)

	matches := c.baseApi.IsZero(c.baseApi.Sub(
		c.baseApi.Mul(x, x),
		xx,
	))
	x = c.baseApi.Select(matches, x, c.baseApi.Mul(x, emulated.NewElement[Ed25519](I))).(EdCoordinate)
	// if (x*x - xx) % Q != 0: x = (x*I) % Q

	odd := c.baseApi.ToBinary(x)[0]
	x = c.baseApi.Select(odd, c.baseApi.Neg(x), x).(EdCoordinate)
	// if x % 2 != 0: x = Q-x

	return x
}

func pow(c *EdCurve, base EdCoordinate, exponent *big.Int) EdCoordinate {
	mul := base
	result := _const(1)
	for exponent.Sign() > 0 {
		if exponent.Bit(0) != 0 {
			result = c.baseApi.Mul(result, mul).(EdCoordinate)
		}
		mul = c.baseApi.Mul(mul, mul).(EdCoordinate)
		exponent.Rsh(exponent, 1)
	}
	return result
}

func swapByteEndianness(in []frontend.Variable) []frontend.Variable {
	if len(in) % 8 != 0 { panic("must be a multiple of 8 bits") }
	result := make([]frontend.Variable, len(in))
	for i := 0; i < len(in); i += 8 {
		for j := 0; j < 8; j++ {
			result[i+j] = in[i+7-j]
		}
	}
	return result
}

// def checkvalid(s, m, pk):
//     if len(s) != 64: raise Exception("signature length is wrong")
//     if len(pk) != 32: raise Exception("public-key length is wrong")
//     R = bytes_to_element(s[:32])
//     A = bytes_to_element(pk)
//     S = bytes_to_scalar(s[32:])
//     h = Hint(s[:32] + pk + m)
//     v1 = Base.scalarmult(S)
//     v2 = R.add(A.scalarmult(h))
//     return v1==v2

// def publickey(seed):
//     # turn first half of SHA512(seed) into scalar, then into point
//     assert len(seed) == 32
//     a = bytes_to_clamped_scalar(H(seed)[:32])
//     A = Base.scalarmult(a)
//     return A.to_bytes()

// def bytes_to_scalar(s):
//     assert len(s) == 32, len(s)
//     return int(binascii.hexlify(s[::-1]), 16)


// from pure25519.basic import (bytes_to_clamped_scalar,
//                              bytes_to_scalar, scalar_to_bytes,
//                              bytes_to_element, Base)
// import hashlib, binascii

// def H(m):
//     return hashlib.sha512(m).digest()

// def Hint(m):
//     h = H(m)
//     return int(binascii.hexlify(h[::-1]), 16)

// def signature(m,sk,pk):
//     assert len(sk) == 32 # seed
//     assert len(pk) == 32
//     h = H(sk[:32])
//     a_bytes, inter = h[:32], h[32:]
//     a = bytes_to_clamped_scalar(a_bytes)
//     r = Hint(inter + m)
//     R = Base.scalarmult(r)
//     R_bytes = R.to_bytes()
//     S = r + Hint(R_bytes + pk + m) * a
//     return R_bytes + scalar_to_bytes(S)

// def checkvalid(s, m, pk):
//     if len(s) != 64: raise Exception("signature length is wrong")
//     if len(pk) != 32: raise Exception("public-key length is wrong")
//     R = bytes_to_element(s[:32])
//     A = bytes_to_element(pk)
//     S = bytes_to_scalar(s[32:])
//     h = Hint(s[:32] + pk + m)
//     v1 = Base.scalarmult(S)
//     v2 = R.add(A.scalarmult(h))
//     return v1==v2

// # wrappers

// import os

// def create_signing_key():
//     seed = os.urandom(32)
//     return seed
// def create_verifying_key(signing_key):
//     return publickey(signing_key)

// def sign(skbytes, msg):
//     """Return just the signature, given the message and just the secret
//     key."""
//     if len(skbytes) != 32:
//         raise ValueError("Bad signing key length %d" % len(skbytes))
//     vkbytes = create_verifying_key(skbytes)
//     sig = signature(msg, skbytes, vkbytes)
//     return sig

// def verify(vkbytes, sig, msg):
//     if len(vkbytes) != 32:
//         raise ValueError("Bad verifying key length %d" % len(vkbytes))
//     if len(sig) != 64:
//         raise ValueError("Bad signature length %d" % len(sig))
//     rc = checkvalid(sig, msg, vkbytes)
//     if not rc:
//         raise ValueError("rc != 0", rc)
//     return True
