package sha512

import (
    "github.com/consensys/gnark/frontend"
)


func T2_512(api frontend.API, a, b, c []frontend.Variable) ([]frontend.Variable) {
	if len(a) != 64 { panic("bad length") }
	if len(b) != 64 { panic("bad length") }
	if len(c) != 64 { panic("bad length") }

	bigsigma0 := BigSigma512(api, a, 28, 34, 39)
	maj := Maj_t512(api, a, b, c)

	return BinSum(api, maj, bigsigma0)
}

// template T2_512() {
//     signal input a[64];
//     signal input b[64];
//     signal input c[64];
//     signal output out[64];
//     var k;

//     component bigsigma0 = BigSigma512(28, 34, 39);
//     component maj = Maj_t512(64);
//     for (k=0; k<64; k++) {
//         bigsigma0.in[k] <== a[k];
//         maj.a[k] <== a[k];
//         maj.b[k] <== b[k];
//         maj.c[k] <== c[k];
//     }
    
//     component sum = BinSum(64, 2);

//     for (k=0; k<64; k++) {
//         sum.in[0][k] <== bigsigma0.out[k];
//         sum.in[1][k] <== maj.out[k];
//     }

//     for (k=0; k<64; k++) {
//         out[k] <== sum.out[k];
//     }
// }
