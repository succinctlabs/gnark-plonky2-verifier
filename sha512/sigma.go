package sha512

import (
    "github.com/consensys/gnark/frontend"
)


func SmallSigma512(api frontend.API, in []frontend.Variable, ra, rb, rc int) ([]frontend.Variable) {
    if len(in) != 64 { panic("bad length") }

    rota := RotR512(api, in, ra)
    rotb := RotR512(api, in, rb)
    shrc := ShR512(api, in, rc)

    return Xor3_512(api, rota, rotb, shrc)
}

// template SmallSigma512(ra, rb, rc) {
//     signal input in[64];
//     signal output out[64];
//     var k;

//     component rota = RotR512(64, ra);
//     component rotb = RotR512(64, rb);
//     component shrc = ShR512(64, rc);

//     for (k=0; k<64; k++) {
//         rota.in[k] <== in[k];
//         rotb.in[k] <== in[k];
//         shrc.in[k] <== in[k];
//     }

//     component xor3 = Xor3_512(64);
//     for (k=0; k<64; k++) {
//         xor3.a[k] <== rota.out[k];
//         xor3.b[k] <== rotb.out[k];
//         xor3.c[k] <== shrc.out[k];
//     }

//     for (k=0; k<64; k++) {
//         out[k] <== xor3.out[k];
//     }
// }

func BigSigma512(api frontend.API, in []frontend.Variable, ra, rb, rc int) ([]frontend.Variable) {
    if len(in) != 64 { panic("bad length") }

    rota := RotR512(api, in, ra)
    rotb := RotR512(api, in, rb)
    rotc := RotR512(api, in, rc)

    return Xor3_512(api, rota, rotb, rotc)
}

// template BigSigma512(ra, rb, rc) {
//     signal input in[64];
//     signal output out[64];
//     var k;

//     component rota = RotR512(64, ra);
//     component rotb = RotR512(64, rb);
//     component rotc = RotR512(64, rc);
//     for (k=0; k<64; k++) {
//         rota.in[k] <== in[k];
//         rotb.in[k] <== in[k];
//         rotc.in[k] <== in[k];
//     }

//     component xor3 = Xor3_512(64);

//     for (k=0; k<64; k++) {
//         xor3.a[k] <== rota.out[k];
//         xor3.b[k] <== rotb.out[k];
//         xor3.c[k] <== rotc.out[k];
//     }

//     for (k=0; k<64; k++) {
//         out[k] <== xor3.out[k];
//     }
// }

