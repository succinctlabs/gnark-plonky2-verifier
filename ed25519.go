// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
    "fmt"
    "os"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/consensys/gnark/std/math/emulated"
)



func main() {
    err := mainImpl()
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}

func mainImpl() error {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	fmt.Println(pubKey)
	fmt.Println(privKey)
	message := []byte("string")
	sig := ed25519.Sign(privKey, message)
	fmt.Println(sig)
	verified := ed25519.Verify(pubKey, message, sig)
	fmt.Println(verified)

	verifiedFalse := ed25519.Verify(pubKey, []byte("string1"), sig)
	fmt.Println(verifiedFalse)

	ele := emulated.NewElement[emulated.BN254Fp](1)
	fmt.Println(ele)

	if err != nil {
		return err
	}
	return nil

}
