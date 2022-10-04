package sha512

import (
    "github.com/consensys/gnark/frontend"
)


func SigmaPlus512(api frontend.API, in2, in7, in15, in16 []frontend.Variable) ([]frontend.Variable) {
    if len(in2) != 64 { panic("bad length") }

    sigma1 := SmallSigma512(in2, 19, 61, 6)
    sigma0 := SmallSigma512(in15, 1, 8, 7)

    return BinSum(sigma1, in7, sigma0, in16)
}


// template SigmaPlus512() {
//     signal input in2[64];
//     signal input in7[64];
//     signal input in15[64];
//     signal input in16[64];
//     signal output out[64];
//     var k;

//     component sigma1 = SmallSigma512(19,61,6);
//     component sigma0 = SmallSigma512(1, 8, 7);
//     for (k=0; k<64; k++) {
//         sigma1.in[k] <== in2[k];
//         sigma0.in[k] <== in15[k];
//     }

//     component sum = BinSum(64, 4);
//     for (k=0; k<64; k++) {
//         sum.in[0][k] <== sigma1.out[k];
//         sum.in[1][k] <== in7[k];
//         sum.in[2][k] <== sigma0.out[k];
//         sum.in[3][k] <== in16[k];
//     }

//     for (k=0; k<64; k++) {
//         out[k] <== sum.out[k];
//     }
// }
