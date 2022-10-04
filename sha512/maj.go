package sha512

import (
	"github.com/consensys/gnark/frontend"
)

func Maj_t512(api frontend.API, a, b, c [] frontend.Variable) ([] frontend.Variable) {
	n := len(a)
	if len(a) != n { panic("bad length") }
	if len(b) != n { panic("bad length") }
	if len(c) != n { panic("bad length") }
	mid := make([] frontend.Variable, n)
	out := make([] frontend.Variable, n)
	for k := 0; k < n; k++ {
		mid[k] = api.Mul(b[k], c[k])
		out[k] = api.Add(api.Mul(a[k], api.Sub(api.Add(b[k], c[k]), api.Mul(2, mid[k]))), mid[k])
	}
	return out
}


// template Maj_t512(n) {
//     signal input a[n];
//     signal input b[n];
//     signal input c[n];
//     signal output out[n];
//     signal mid[n];

//     for (var k=0; k<n; k++) {
//         mid[k] <== b[k]*c[k];
//         out[k] <== a[k] * (b[k]+c[k]-2*mid[k]) + mid[k];
//     }
// }