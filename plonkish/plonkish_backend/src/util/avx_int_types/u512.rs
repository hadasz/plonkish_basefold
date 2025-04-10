
use rand::SeedableRng;
use crate::util::avx_int_types::B128;
use crate::util::Serializer;
use crate::util::Deserializer;
use crate::util::Deserialize;
use crate::util::Serialize;
use core::simd::u8x64;
use core::arch::x86_64::{_mm512_xor_epi64,_mm512_and_epi64};
use core::simd::u64x8;
use rayon::iter::ParallelIterator;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use core::ops::{BitXor,Add, BitAnd};
use num_traits::Zero;
use crate::util::avx_int_types::BlazeField;
use core::arch::x86_64::__m512i as u512;
#[derive(Clone,Copy,Debug)]
pub struct Blazeu512{
    pub value: u512
}
impl Default for Blazeu512{
    fn default() -> Self {
       todo!()
    }
}
impl BlazeField for Blazeu512{
    type IntType = u512;
    type NumBytes = u8x64;
 
    fn get_value(&self) -> Self::IntType{
        self.value
    }

    fn to_le_bytes(&self) -> Self::NumBytes{
       u8x64::from(self.value)
    }
    fn from_le_bytes(bytes:Self::NumBytes) -> Self { 
        Self { value: u512::from(bytes) }
    }

     fn rand_vec(length: usize) -> Vec<Self> {
        let mut rng = ChaCha8Rng::from_entropy();
        let mut dest : Vec<u512> = vec![Self::zero().value;length];
        dest.par_iter_mut().enumerate().for_each(|(i, x)| {
            let mut rng1 = rng.clone();
            let mut bytes = [0u8;64];
            rng1.fill_bytes(&mut bytes);
            *x = u512::from(u8x64::from_array(bytes));
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

impl Serialize for Blazeu512{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
       todo!()
    }
}
impl<'de> Deserialize<'de> for Blazeu512{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!()
    }
    }






impl BitXor for Blazeu512{
    type Output = Self;

    fn bitxor(self,rhs: Self) -> Self{
        unsafe{ Self{ value: _mm512_xor_epi64(self.value,rhs.value)} }
    }
}

impl BitAnd for Blazeu512{
    type Output = Self;
    fn bitand(self,rhs:Self) -> Self{
        unsafe{ Self{ value: _mm512_and_epi64(self.value,rhs.value) } }
    }
}


impl Zero for Blazeu512{
    fn zero() -> Blazeu512{
        Self { value: u512::from(u8x64::from_array([0;64])) }
    }
    fn is_zero(&self) -> bool { todo!() }
}

impl Add for Blazeu512{
    type Output = Self;
    fn add(self,rhs:Self) -> Self{
        todo!()
    }
}
impl PartialEq for Blazeu512{
    fn eq(&self, other:&Self) -> bool{
        u8x64::from(self.value) == u8x64::from(other.value)
    }
}

unsafe impl Send for Blazeu512{}

unsafe impl Sync for Blazeu512 {}