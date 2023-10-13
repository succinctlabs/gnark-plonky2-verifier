# Gnark Plonky2 Verifier

This is an implementation of a [Plonky2](https://github.com/mir-protocol/plonky2) verifier in Gnark (supports Groth16 and PLONK).

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

## Profiling

First run the benchmark with profiling turned on
```
go run benchmark.go -profile
```

Then use the following command to generate a visualization of the pprof
```
go tool pprof --png gnark.pprof > verifier.png
```