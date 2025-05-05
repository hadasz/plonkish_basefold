## Basefold

**This is a fork of https://github.com/han0110/plonkish**, that includes an implementation of BasefoldPCS, Blaze and an implementation of the Zeromorph compilation of FRI (for benchmarking purposes)

**The code for Basefold is located in `plonkish_backend/src/pcs/multilinear/basefold.rs`**

**The code for Blaze is located in `plonkish_backend/src/pcs/multilinear/blaze.rs`**

To test Basefold, go to `plonkish/plonkish_backend/src/pcs/multilinear` and run `rustup run nightly cargo test basefold::test::commit` or `rustup run nightly cargo test basefold::test::batch_commit`. To test Blaze, run `rustup run nightly cargo test blaze::test::bench_commit`. 

To benchmark, go to `plonkish/benchmark` and run `rustup run nightly cargo bench`. You can change which benchmarks are run in `plonkish/benchmark/Cargo.toml`. Blaze benchmarks are in `blaze_bench.rs`

The util folder (`plonky2_util`) and much inspriation was taken from `plonky2` (https://github.com/0xPolygonZero/plonky2)

Additive Binary RS implementation in Blaze was taken from `Binius` (https://github.com/IrreducibleOSS/binius)
