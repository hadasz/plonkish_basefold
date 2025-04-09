use crate::util::arithmetic::Field;
use core::fmt::Debug;
use serde::de::DeserializeOwned;
use rand_chacha::ChaCha8Rng;
use core::ops::{BitAnd,BitXor};
use num_traits::ops::bytes::NumBytes;
use crate::util::binary_extension_fields::B128;
use num_traits::Zero;

use std::marker::Sync;
use std::marker::Send;
use serde::{Deserialize,Serialize};

pub mod u64; 
pub mod u512;
pub mod u256;
pub mod u64x8;
pub trait BlazeField: Zero + BitXor<Output = Self>+ Send + Clone + Copy + Sync + BitAnd<Output = Self> +  Serialize + DeserializeOwned + Debug + Default + 'static + PartialEq{
    type IntType;
    type NumBytes: AsRef<[u8]> + AsMut<[u8]>;

    fn get_value(&self) -> Self::IntType;

    fn to_le_bytes(&self) -> Self::NumBytes;

    fn from_le_bytes(bytes:Self::NumBytes) -> Self;

    fn to_int_type(&self) -> Self::IntType {
        self.get_value()
    }

    fn rand_vec(length: usize) -> Vec<Self>;

    fn count_ones(&self) -> u32;

    fn from_hash(hash:&[u8]) -> Self;

    fn to_b128(&self) -> B128; 

    fn from_b128(val:B128) -> Vec<Self>{
        todo!()
    }
    fn to_b128_vec(data:Vec<Self>) -> B128{
        todo!()
    }
}

