mod brakedown;
mod raa;
mod binary_rs;
pub use raa::{encode_bits, encode_bits_long, Permutation,repetition_code_long, serial_accumulator_long,encode_bits_ser};
pub use brakedown::{
    Brakedown, BrakedownSpec, BrakedownSpec1, BrakedownSpec2, BrakedownSpec3, BrakedownSpec4,
    BrakedownSpec5, BrakedownSpec6,
};

pub trait LinearCodes<F>: Sync + Send {
    fn row_len(&self) -> usize;

    fn codeword_len(&self) -> usize;

    fn num_column_opening(&self) -> usize;

    fn num_proximity_testing(&self) -> usize;

    fn encode(&self, input: impl AsMut<[F]>);
}
