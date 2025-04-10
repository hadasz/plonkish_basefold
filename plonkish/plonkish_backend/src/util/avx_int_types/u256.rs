

use rand::SeedableRng;
use crate::util::avx_int_types::B128;
use core::simd::u8x32;
use crate::util::Serializer;
use crate::util::Deserializer;
use crate::util::Deserialize;
use crate::util::Serialize;
use core::simd::u8x64;
use core::arch::x86_64::{_mm256_xor_epi64,_mm256_and_si256};
use core::simd::u64x8;
use rayon::iter::ParallelIterator;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use core::ops::{BitXor,Add, BitAnd};
use num_traits::Zero;
use crate::util::avx_int_types::BlazeField;
use core::arch::x86_64::__m256i as u256;
#[derive(Clone,Copy,Debug)]
pub struct Blazeu256{
    pub value: u256
}
impl BlazeField for Blazeu256{
    type IntType = u256;
    type NumBytes = u8x32;
 
    fn get_value(&self) -> Self::IntType{
        self.value
    }

    fn to_le_bytes(&self) -> Self::NumBytes{
       u8x32::from(self.value)
    }
    fn from_le_bytes(bytes:Self::NumBytes) -> Self { 
        Self { value: u256::from(bytes) }
    }
     fn rand_vec(length: usize) -> Vec<Self> {
        let mut rng = ChaCha8Rng::from_entropy();
        let mut dest : Vec<u256> = vec![Self::zero().value;length];
        dest.par_iter_mut().enumerate().for_each(|(i, x)| {
            let mut rng1 = rng.clone();
            let mut bytes = [0u8;32];
            rng1.fill_bytes(&mut bytes);
            *x = u256::from(u8x32::from_array(bytes));
        });
        dest.iter().map(|x|{ Self{ value: *x}}).collect::<Vec<Self>>()
    }

    fn count_ones(&self) -> u32{
        todo!();
    }
    fn from_hash(hash:&[u8]) -> Self{
        todo!();
    }
    fn to_b128(&self) -> B128 { todo!() }
}

impl Default for Blazeu256{
    fn default() -> Self {
       todo!()
    }
}

impl Serialize for Blazeu256{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
       todo!()
    }
}
impl<'de> Deserialize<'de> for Blazeu256{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!()
    }
    }






impl BitXor for Blazeu256{
    type Output = Self;

    fn bitxor(self,rhs: Self) -> Self{
        unsafe{ Self{ value: _mm256_xor_epi64(self.value,rhs.value)} }
    }
}

impl BitAnd for Blazeu256{
    type Output = Self;
    fn bitand(self,rhs:Self) -> Self{
        unsafe{ Self{ value: _mm256_and_si256(self.value,rhs.value) } }
    }
}


impl Zero for Blazeu256{
    fn zero() -> Blazeu256{
        Self { value: u256::from(u8x32::from_array([0;32])) }
    }
    fn is_zero(&self) -> bool { todo!() }
}

impl Add for Blazeu256{
    type Output = Self;
    fn add(self,rhs:Self) -> Self{
        todo!()
    }
}

impl PartialEq for Blazeu256{
    fn eq(&self, other:&Self) -> bool{
        u8x32::from(self.value) == u8x32::from(other.value)
    }
}

unsafe impl Send for Blazeu256{}

unsafe impl Sync for Blazeu256 {}