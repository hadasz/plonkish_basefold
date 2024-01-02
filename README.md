## Basefold

This is a fork of https://github.com/han0110/plonkish, that includes an implementation of BasefoldPCS and an implementation of the Zeromorph compilation of FRI (for benchmarking purposes)

Basefold is located in plonkish_backend/src/pcs/multilinear/basefold.rs

To test, go to `plonkish/plonkish_backend/src/pcs/multilinear` and run `rustup run nightly cargo test basefold::test::commit` or `rustup run nightly cargo test basefold::test::batch_commit`

To benchmark, go to `plonkish/benchmark` and run `rustup run nightly cargo bench`. You can change which benchmarks are run in `plonkish/benchmark/Cargo.toml`

