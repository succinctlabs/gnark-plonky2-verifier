package sha512

import (
	"github.com/consensys/gnark/frontend"
)

func Sha512(api frontend.API, in [] frontend.Variable) ([512] frontend.Variable) {
	nBits := len(in)

	nBlocks := ((nBits + 128) / 1024) + 1

	paddedIn := make([] frontend.Variable, nBlocks * 1024)

	for k := 0; k < nBits; k++ {
		paddedIn[k] = in[k]
	}
	paddedIn[nBits] = 1

	for k := nBits+1; k < len(paddedIn); k++ {
		paddedIn[k] = 0
	}

	for k := 0; k < 128; k++ {
		paddedIn[nBlocks*1024 - k - 1] = (nBits >> k) & 1
	}

	var h512Components [8][64]frontend.Variable

	for i := 0; i < 8; i++ {
		h512Components[i] = H512(uint(i))
	}

	sha512compression := make([][] frontend.Variable, nBlocks)
	
	for i := 0; i < nBlocks; i++ {
		var hin = make([] frontend.Variable, 64 * 8)
		var inp = make([] frontend.Variable, 1024)
		if i == 0 {
			for k := 0; k < 64; k++ {
				for j := 0; j < 8; j++ {
					hin[j*64 + k] = h512Components[j][k]
				}
			}
		} else {
			for k := 0; k < 64; k++ {
				for j := 0; j < 8; j++ {
					hin[j*64 + k] = sha512compression[i-1][64*j+63-k]
				}
			}
		}
		for k := 0; k < 1024; k++ {	
			inp[k] = paddedIn[i*1024 + k]
		}
		sha512compression[i] = Sha512compression(api, hin, inp)
	}

	var out [512]frontend.Variable

	for k := 0; k < 512; k++ {
		out[k] = sha512compression[nBlocks-1][k]

	}

	return out
}
