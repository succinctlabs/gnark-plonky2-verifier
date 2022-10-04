package sha512

import (
	"math/big"
    "github.com/consensys/gnark/backend/hint"
    "github.com/consensys/gnark/frontend"
)


func padToSameLength(args [][]frontend.Variable) ([][]frontend.Variable, int) {
	maxLength := 0
	for _, v := range args {
		if len(v) > maxLength {
			maxLength = len(v)
		}
	}
	result := make([][]frontend.Variable, len(args))
	for i := 0; i < len(args); i++ {
		if len(args[i]) < maxLength {
			arr := make([]frontend.Variable, maxLength)
			for j := 0; j < maxLength; j++ {
				if j < len(args[i]) {
					arr[j] = args[i][j]
				} else {
					arr[j] = 0
				}
			}
			result[i] = arr
		} else {
			result[i] = args[i]
		}
	}
	return result, maxLength
}

func log2(n int) int {
	if n <= 0 { panic("undefined") }
	result := 0
	n -= 1
	for n > 0 {
		n >>= 1
		result += 1
	}
	return result
}

func extractBit(n big.Int) bool {
	if !n.IsInt64() {
		panic("not bit")
	}
	val := n.Int64()
	if val == 0 {
		return false
	} else if val == 1 {
		return true
	} else {
		panic("not bit")
	}
}

func flatten(arr [][]frontend.Variable) ([]frontend.Variable) {
	totalLength := 0
	for _, v := range arr {
		totalLength += len(v)
	}
	result := make([]frontend.Variable, totalLength)
	i := 0
	for _, v := range arr {
		for _, u := range v {
			result[i] = u
			i += 1
		}
	}
	return result
}

func BinSum(api frontend.API, args ...[]frontend.Variable) ([]frontend.Variable) {
	ops := len(args)
	in, n := padToSameLength(args)
	nout := n + log2(ops)
//     var nout = nbits((2**n -1)*ops);
//     signal input in[ops][n];
//     signal output out[nout];

	var hintFn hint.Function = func(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
		if len(inputs) != ops*n { panic("bad length") }
		if len(outputs) != nout { panic("bad length") }

		maxOutputValue := big.NewInt(1)
		maxOutputValue.Lsh(maxOutputValue, uint(nout))
		if maxOutputValue.Cmp(field) != -1 { panic("overflow") }

		result := big.NewInt(0)
		for i := 0; i < ops; i++ {
			placeValue := big.NewInt(1)
			for j := 0; j < n; j++ {
				if extractBit(*inputs[i*n+j]) {
					result.Add(result, placeValue)
				}
				placeValue.Add(placeValue, placeValue)
			}
		}
		for i := 0; i < nout; i++ {
			v := new(big.Int).Rsh(result, uint(i))
			v.And(v, big.NewInt(1))
			outputs[i] = v
		}
		return nil
	}

	out, err := api.NewHint(hintFn, nout, flatten(in)...)
	if err != nil {
		panic(err)
	}

	var lhs frontend.Variable = 0
	var rhs frontend.Variable = 0

	placeValue := big.NewInt(1)
	for i := 0; i < nout; i++ {
		for j := 0; j < ops; j++ {
			if i < n {
				lhs = api.Add(lhs, api.Mul(placeValue, in[j][i]))
			}
		}
		rhs = api.Add(rhs, api.Mul(placeValue, out[i]))
		api.AssertIsBoolean(out[i])
		placeValue.Add(placeValue, placeValue)
	}
	api.AssertIsEqual(lhs, rhs)

	return out
}
