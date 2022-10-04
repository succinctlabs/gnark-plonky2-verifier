package sha512

import (
    "github.com/consensys/gnark/frontend"
)


func Sha512compression(api frontend.API, hin, inp []frontend.Variable) ([]frontend.Variable) {
	if len(hin) != 512 { panic("bad length") }
	if len(inp) != 1024 { panic("bad length") }

	var ct_k [80][]frontend.Variable
	for i := 0; i < 80; i++ {
		ct_k[i] = K512(i)
	}

	var a [81][64]frontend.Variable
	var b [81][64]frontend.Variable
	var c [81][64]frontend.Variable
	var d [81][64]frontend.Variable
	var e [81][64]frontend.Variable
	var f [81][64]frontend.Variable
	var g [81][64]frontend.Variable
	var h [81][64]frontend.Variable
	var w [80][64]frontend.Variable

	for t := 0; t < 80; t++ {
		if t < 16 {
			for k := 0; k < 64; k++ {
				w[t][k] = inp[t*64+63-k]
			}
		} else {
			w[t] = SigmaPlus512(w[t-2], w[t-7], w[t-15], w[t-16])
		}
		// if (t<16) {
		//     for (k=0; k<64; k++) {
		//         w[t][k] <== inp[t*64+63-k];
		//     }
		// } else {
		//     for (k=0; k<64; k++) {
		//         sigmaPlus[t-16].in2[k] <== w[t-2][k];
		//         sigmaPlus[t-16].in7[k] <== w[t-7][k];
		//         sigmaPlus[t-16].in15[k] <== w[t-15][k];
		//         sigmaPlus[t-16].in16[k] <== w[t-16][k];
		//     }
		//     for (k=0; k<64; k++) {
		//         w[t][k] <== sigmaPlus[t-16].out[k];
		//     }
		// }
	}


	for k := 0; k < 64; k++ {
	    a[0][k] = hin[k]
	    b[0][k] = hin[64*1 + k]
	    c[0][k] = hin[64*2 + k]
	    d[0][k] = hin[64*3 + k]
	    e[0][k] = hin[64*4 + k]
	    f[0][k] = hin[64*5 + k]
	    g[0][k] = hin[64*6 + k]
	    h[0][k] = hin[64*7 + k]
	}
	// for (k=0; k<64; k++ ) {
	//     a[0][k] <== hin[k];
	//     b[0][k] <== hin[64*1 + k];
	//     c[0][k] <== hin[64*2 + k];
	//     d[0][k] <== hin[64*3 + k];
	//     e[0][k] <== hin[64*4 + k];
	//     f[0][k] <== hin[64*5 + k];
	//     g[0][k] <== hin[64*6 + k];
	//     h[0][k] <== hin[64*7 + k];
	// }


	for t := 0; t < 80; t++ {
		t1 := T1_512(h[t], e[t], f[t], g[t], ct_k[t], w[t])
		t2 := T2_512(a[t], b[t], c[t])
	//     for (k=0; k<64; k++) {
	//         t1[t].h[k] <== h[t][k];
	//         t1[t].e[k] <== e[t][k];
	//         t1[t].f[k] <== f[t][k];
	//         t1[t].g[k] <== g[t][k];
	//         t1[t].k[k] <== ct_k[t].out[k];
	//         t1[t].w[k] <== w[t][k];

	//         t2[t].a[k] <== a[t][k];
	//         t2[t].b[k] <== b[t][k];
	//         t2[t].c[k] <== c[t][k];
	//     }

		sume := BinSum(d[t], t1)
		suma := BinSum(t1, t2)
	//     for (k=0; k<64; k++) {
	//         sume[t].in[0][k] <== d[t][k];
	//         sume[t].in[1][k] <== t1[t].out[k];

	//         suma[t].in[0][k] <== t1[t].out[k];
	//         suma[t].in[1][k] <== t2[t].out[k];
	//     }

		for k := 0; k < 64; k++ {
	        h[t+1][k] = g[t][k];
	        g[t+1][k] = f[t][k];
	        f[t+1][k] = e[t][k];
	        e[t+1][k] = sume[k];
	        d[t+1][k] = c[t][k];
	        c[t+1][k] = b[t][k];
	        b[t+1][k] = a[t][k];
	        a[t+1][k] = suma[k];
		}
	//     for (k=0; k<64; k++) {
	//         h[t+1][k] <== g[t][k];
	//         g[t+1][k] <== f[t][k];
	//         f[t+1][k] <== e[t][k];
	//         e[t+1][k] <== sume[t].out[k];
	//         d[t+1][k] <== c[t][k];
	//         c[t+1][k] <== b[t][k];
	//         b[t+1][k] <== a[t][k];
	//         a[t+1][k] <== suma[t].out[k];
	//     }
	}

	var fsum_in [8][2][64]frontend.Variable

	for k := 0; k < 64; k++ {
	    fsum[0][0][k] =  hin[64*0+k]
	    fsum[0][1][k] =  a[80][k]
	    fsum[1][0][k] =  hin[64*1+k]
	    fsum[1][1][k] =  b[80][k]
	    fsum[2][0][k] =  hin[64*2+k]
	    fsum[2][1][k] =  c[80][k]
	    fsum[3][0][k] =  hin[64*3+k]
	    fsum[3][1][k] =  d[80][k]
	    fsum[4][0][k] =  hin[64*4+k]
	    fsum[4][1][k] =  e[80][k]
	    fsum[5][0][k] =  hin[64*5+k]
	    fsum[5][1][k] =  f[80][k]
	    fsum[6][0][k] =  hin[64*6+k]
	    fsum[6][1][k] =  g[80][k]
	    fsum[7][0][k] =  hin[64*7+k]
	    fsum[7][1][k] =  h[80][k]
	}
	// for (k=0; k<64; k++) {
	//     fsum[0].in[0][k] <==  hin[64*0+k];
	//     fsum[0].in[1][k] <==  a[80][k];
	//     fsum[1].in[0][k] <==  hin[64*1+k];
	//     fsum[1].in[1][k] <==  b[80][k];
	//     fsum[2].in[0][k] <==  hin[64*2+k];
	//     fsum[2].in[1][k] <==  c[80][k];
	//     fsum[3].in[0][k] <==  hin[64*3+k];
	//     fsum[3].in[1][k] <==  d[80][k];
	//     fsum[4].in[0][k] <==  hin[64*4+k];
	//     fsum[4].in[1][k] <==  e[80][k];
	//     fsum[5].in[0][k] <==  hin[64*5+k];
	//     fsum[5].in[1][k] <==  f[80][k];
	//     fsum[6].in[0][k] <==  hin[64*6+k];
	//     fsum[6].in[1][k] <==  g[80][k];
	//     fsum[7].in[0][k] <==  hin[64*7+k];
	//     fsum[7].in[1][k] <==  h[80][k];
	// }

	var fsum [8][]frontend.Variable
	for i := 0; i < 8; i++ {
		fsum[i] = BinSum(fsum_in[i][0], fsum_in[i][1])
	}

	var out [512]frontend.Variable

	for k := 0; k < 64; k++ {
	    out[63-k]     = fsum[0][k]
	    out[64+63-k]  = fsum[1][k]
	    out[128+63-k]  = fsum[2][k]
	    out[192+63-k]  = fsum[3][k]
	    out[256+63-k] = fsum[4][k]
	    out[320+63-k] = fsum[5][k]
	    out[384+63-k] = fsum[6][k]
	    out[448+63-k] = fsum[7][k]
	}
	// for (k=0; k<64; k++) {
	//     out[63-k]     <== fsum[0].out[k];
	//     out[64+63-k]  <== fsum[1].out[k];
	//     out[128+63-k]  <== fsum[2].out[k];
	//     out[192+63-k]  <== fsum[3].out[k];
	//     out[256+63-k] <== fsum[4].out[k];
	//     out[320+63-k] <== fsum[5].out[k];
	//     out[384+63-k] <== fsum[6].out[k];
	//     out[448+63-k] <== fsum[7].out[k];
	// }
	return out
}
