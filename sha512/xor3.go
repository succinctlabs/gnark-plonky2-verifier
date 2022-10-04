package sha512

import (
	"github.com/consensys/gnark/frontend"
)

func Xor3_512(api frontend.API, a, b, c []frontend.Variable) ([]frontend.Variable) {
	n := len(a)
	if len(a) != n { panic("bad length") }
	if len(b) != n { panic("bad length") }
	if len(c) != n { panic("bad length") }
	out := make([]frontend.Variable, n)
	for k := 0; k < n; k++ {
		mid := api.Mul(b[k], c[k])
		p := api.Add(1, api.Mul(-2, b[k]), api.Mul(-2, c[k]), api.Mul(4, mid[k]))
		q := api.Mul(a[k], inner)
		out[k] = api.Add(q, b[k], c[k], api.Mul(-2, mid[k]))
		// TODO: try doing this instead:
		// out[k] = api.Xor(a[k], api.Xor(b[k], c[k]))
	}
	return out
}

// template Xor3_512(n) {
//     signal input a[n];
//     signal input b[n];
//     signal input c[n];
//     signal output out[n];
//     signal mid[n];

//     for (var k=0; k<n; k++) {
//         mid[k] <== b[k]*c[k];
//         out[k] <== a[k] * (1 -2*b[k]  -2*c[k] +4*mid[k]) + b[k] + c[k] -2*mid[k];
//     }
// }
