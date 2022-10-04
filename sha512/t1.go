package sha512

import (
    "github.com/consensys/gnark/frontend"
)


func T1_512(api frontend.API, h, e, f, g, k, w []frontend.Variable) ([]frontend.Variable) {
    if len(h) != 64 { panic("bad length") }
    if len(e) != 64 { panic("bad length") }
    if len(f) != 64 { panic("bad length") }
    if len(g) != 64 { panic("bad length") }
    if len(k) != 64 { panic("bad length") }
    if len(w) != 64 { panic("bad length") }

    ch := Ch_t512(e, f, g)
    bigsigma1 := BigSigma512(e, 14, 18, 41)

    return BinSum(h, bigsigma1, ch, k, w)
}

// template T1_512() {
//     signal input h[64];
//     signal input e[64];
//     signal input f[64];
//     signal input g[64];
//     signal input k[64];
//     signal input w[64];
//     signal output out[64];

//     var ki;

//     component ch = Ch_t512(64);
//     component bigsigma1 = BigSigma512(14, 18, 41);

//     for (ki=0; ki<64; ki++) {
//         bigsigma1.in[ki] <== e[ki];
//         ch.a[ki] <== e[ki];
//         ch.b[ki] <== f[ki];
//         ch.c[ki] <== g[ki];
//     }

//     component sum = BinSum(64, 5);
//     for (ki=0; ki<64; ki++) {
//         sum.in[0][ki] <== h[ki];
//         sum.in[1][ki] <== bigsigma1.out[ki];
//         sum.in[2][ki] <== ch.out[ki];
//         sum.in[3][ki] <== k[ki];
//         sum.in[4][ki] <== w[ki];
//     }

//     for (ki=0; ki<64; ki++) {
//         out[ki] <== sum.out[ki];
//     }
// }
