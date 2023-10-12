# gnark-plonky2-verifier

This is an in-progress implementation of a [Plonky2](https://github.com/mir-protocol/plonky2) verifier in Gnark (supports Groth16 and PLONK). It currently is able to verify some dummy circuits, but not much more as many of the custom gates used in Plonky2 are currently not implemented.

Besides the verifier, there are some Gnark implementation of circuits in this repo that may be useful for other projects:

- [Goldilocks](https://github.com/succinctlabs/gnark-plonky2-verifier/blob/main/field/field.go)
- [Poseidon](https://github.com/succinctlabs/gnark-plonky2-verifier/blob/main/poseidon/poseidon.go)
- [FRI](https://github.com/succinctlabs/gnark-plonky2-verifier/blob/main/plonky2_verifier/fri.go)

## Requirements

- [Go (1.20.1+)](https://go.dev/doc/install)

## Benchmark

To run the benchmark,
```
go run benchmark.go
```

Here are relevant numbers from a benchmark ran on an M1 Max with 10 CPU cores.

```
11:04:08 INF compiling circuit
11:04:08 INF parsed circuit inputs nbPublic=0 nbSecret=0
11:12:30 INF building constraint system nbConstraints=6740784
Generating witness 2023-03-28 11:12:42.702566 -0700 PDT m=+514.333410376
Running circuit setup 2023-03-28 11:12:42.702666 -0700 PDT m=+514.333509834
Creating proof 2023-03-28 11:18:58.881518 -0700 PDT m=+890.519971543
11:18:59 DBG constraint system solver done backend=groth16 nbConstraints=6740784 took=675.361625
11:19:10 DBG prover done backend=groth16 curve=bn254 nbConstraints=6740784 took=10512.664584
Verifying proof 2023-03-28 11:19:10.169636 -0700 PDT m=+901.808314709
11:19:10 DBG verifier done backend=groth16 curve=bn254 took=6.288792
bn254 2023-03-28 11:19:10.175992 -0700 PDT m=+901.814670834
```

The circuit can be significantly optimized by using more efficient arithmetic for Goldilocks, among other things.
