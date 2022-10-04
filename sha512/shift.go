package sha512

import (
	"github.com/consensys/gnark/frontend"
)

func ShR512(api frontend.API, in []frontend.Variable, r int) ([]frontend.Variable) {
	n := len(in)
	out := make([] frontend.Variable, n)
	for i := 0; i < n; i++ {
		if i+r >= n {
			out[i] = 0
		} else {
			out[i] = in[i+r]
		}
	}
	return out
}


// template ShR512(n, r) {
//     signal input in[n];
//     signal output out[n];

//     for (var i=0; i<n; i++) {
//         if (i+r >= n) {
//             out[i] <== 0;
//         } else {
//             out[i] <== in[ i+r ];
//         }
//     }
// }
