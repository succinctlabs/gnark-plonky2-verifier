# gnark-plonky2-verifier

This is an in-progress implementation of a [Plonky2](https://github.com/mir-protocol/plonky2) verifier in Gnark. It currently is able to verify some dummy circuits, but not much more as many of the custom gates used in Plonky2 are currently not implemented.

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
# of constraints:  6740784
circuit compilation time:  19 minutes, 33 sec.
witness generation time: < 1 second
groth16 setup:  8 minutes 23 seconds
proof generation: 23 seconds
proof verification: < 1 second
```

The circuit can be significantly optimized by using more efficient arithmetic for Goldilocks, among other things.