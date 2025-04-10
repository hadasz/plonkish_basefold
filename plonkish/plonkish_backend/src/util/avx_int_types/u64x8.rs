
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
pub struct Blazeu64x8{
    pub value: u64x8
}
impl Default for Blazeu64x8{
    fn default() -> Self {
       todo!()
    }
}
impl BlazeField for Blazeu64x8{
    type IntType = u64x8;
    type NumBytes = [u8;64];
 
    fn get_value(&self) -> Self::IntType{
        self.value
    }

    fn to_le_bytes(&self) -> Self::NumBytes{
        let arr = self.value.to_array();
        let bytes:[u8;64] = arr.to_vec().iter().map(|x| x.to_le_bytes()).flatten().collect::<Vec<_>>().try_into().ok().unwrap();
        bytes
    }
    fn from_le_bytes(bytes:Self::NumBytes) -> Self { 

        let val = bytes.to_vec().chunks(8).map(|x|{
            u64::from_le_bytes(x.try_into().ok().unwrap()) //TODO: Throw an error here?
        }).collect::<Vec<_>>();

        Self { value: u64x8::from_slice(&val[..]) }
    }

     fn rand_vec(length: usize) -> Vec<Self> {
        let mut rng = ChaCha8Rng::from_entropy();
        let mut dest : Vec<Self> = vec![Self::from_le_bytes([0u8;64]);length];
        dest.par_iter_mut().enumerate().for_each(|(i, x)| {
            let mut rng1 = rng.clone();
            let mut bytes = [0u8;64];
            rng1.fill_bytes(&mut bytes);
            *x = Self::from_le_bytes(bytes);
        });
        dest
    }

    fn count_ones(&self) -> u32{
        todo!();
    }
    fn from_hash(hash:&[u8]) -> Self{
        todo!();
    }
    fn to_b128(&self) -> B128 { todo!() }
}

impl Serialize for Blazeu64x8{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
       todo!()
    }
}
impl<'de> Deserialize<'de> for Blazeu64x8{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!()
    }
    }






impl BitXor for Blazeu64x8{
    type Output = Self;

    fn bitxor(self,rhs: Self) -> Self{
        Self{ value: self.value.bitxor(rhs.value) }
    }
}

impl BitAnd for Blazeu64x8{
    type Output = Self;
    fn bitand(self,rhs:Self) -> Self{
        Self{value: self.value & rhs.value }
    }
}


impl Zero for Blazeu64x8{
    fn zero() -> Blazeu64x8{
       Self::from_le_bytes([0u8;64])
    }
    fn is_zero(&self) -> bool { todo!() }
}

impl Add for Blazeu64x8{
    type Output = Self;
    fn add(self,rhs:Self) -> Self{
        todo!()
    }
}

impl PartialEq for Blazeu64x8{
    fn eq(&self, other:&Self) -> bool{
        self.value == other.value
    }
}
unsafe impl Send for Blazeu64x8{}

unsafe impl Sync for Blazeu64x8 {}