package sha512

import (
	"github.com/consensys/gnark/frontend"
)

func Ch_t512(api frontend.API, a, b, c []frontend.Variable) ([]frontend.Variable) {
	n := len(a)
	if len(a) != n { panic("bad length") }
	if len(b) != n { panic("bad length") }
	if len(c) != n { panic("bad length") }
	out := make([]frontend.Variable, n)
	for k := 0; k < n; k++ {
		out[k] = api.Add(api.Mul(a[k], api.Sub(b[k], c[k])), c[k]);
	}
	return out
}

// template Ch_t512(n) {
//     signal input a[n];
//     signal input b[n];
//     signal input c[n];
//     signal output out[n];

//     for (var k=0; k<n; k++) {
//         out[k] <== a[k] * (b[k]-c[k]) + c[k];
//     }
// }
