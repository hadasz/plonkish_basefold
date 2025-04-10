
use rand::SeedableRng;
use crate::util::avx_int_types::B128;
use num_integer::Integer;
use crate::util::BigUint;
use rayon::iter::ParallelIterator;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use core::ops::{BitXor,Add, BitAnd};
use num_traits::Zero;
use crate::util::avx_int_types::BlazeField;
use serde::{Serialize, Deserialize};

#[derive(Clone,Copy,Debug,Serialize,Deserialize)]
#[derive(PartialEq)]
pub struct Blazeu64{
    pub value: u64
}
impl Default for Blazeu64{
    fn default() -> Self {
       todo!()
    }
}
impl BlazeField for Blazeu64{
    type IntType = u64;
    type NumBytes = [u8;8];
 
    fn get_value(&self) -> Self::IntType{
        self.value
    }

    fn to_le_bytes(&self) -> Self::NumBytes{
        self.value.to_le_bytes()
    }
    fn from_le_bytes(bytes:Self::NumBytes) -> Self { 
        Self{ value: u64::from_le_bytes(bytes) }
    }

     fn rand_vec(length: usize) -> Vec<Self> {
        let mut rng = ChaCha8Rng::from_entropy();
        let mut dest : Vec<u64> = vec![u64::zero();length];
        dest.par_iter_mut().enumerate().for_each(|(i, x)| {
            let mut rng1 = rng.clone();
            let mut bytes = [0, 0, 0, 0, 0, 0, 0, 0];
            rng1.set_word_pos(i as u128);
            rng1.fill_bytes(&mut bytes);
            *x = u64::from_le_bytes(bytes);
        });
        dest.iter().map(|x|{ Self{ value: *x}}).collect::<Vec<Self>>()
    }

    fn count_ones(&self) -> u32{
        self.value.count_ones()
    }
    fn from_hash(hash:&[u8]) -> Self{
        let rem = BigUint::from_bytes_le(hash.as_ref()).div_rem(&BigUint::from(u64::MAX)).1;
        let value = u64::try_from(&rem).ok().unwrap();
        Self{ value }
    }
    fn to_b128(&self) -> B128 {
        B128::from(self.get_value())
    }
    fn from_b128(val:B128) -> Vec<Self>{
        vec![Self{ value: val.value[0]}, Self{ value: val.value[1]}]
    }
    fn to_b128_vec(data:Vec<Self>) -> B128{
        B128{ value: [ data[0].value, data[1].value]}
    }
}
#[test]
fn test_from_hash(){
    let bits = vec![3u8;32]; 
    let slice:&[u8] = &bits[..];
    Blazeu64::from_hash(slice);
}

impl BitXor for Blazeu64{
    type Output = Self;

    fn bitxor(self,rhs: Self) -> Self{
        Self{ value: self.value ^ rhs.value}
    }
}

impl BitAnd for Blazeu64{
    type Output = Self;
    fn bitand(self,rhs:Self) -> Self{
        Self{ value: self.value & rhs.value }
    }
}


impl Zero for Blazeu64{
    fn zero() -> Blazeu64{
        Self { value: 0u64 }
    }
    fn is_zero(&self) -> bool { todo!() }
}

impl Add for Blazeu64{
    type Output = Self;

    fn add(self,rhs:Self) -> Self::Output{
        Self{ value: self.value + rhs.value}
    }
}

unsafe impl Send for Blazeu64{}

unsafe impl Sync for Blazeu64 {}