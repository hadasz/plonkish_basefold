use crate::util::avx_int_types::{u512::Blazeu512,u64x8::Blazeu64x8,u256::Blazeu256};
use num_traits::Zero;
use crate::util::{arithmetic::div_ceil,avx_int_types::{BlazeField,u64::Blazeu64}};
use ff::{BatchInvert, PrimeField, PrimeFieldBits};

use rand::prelude::IteratorRandom;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha12Rng, ChaCha8Rng,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

use rayon::prelude::*;
use std::collections::HashMap;


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Permutation{
    pub permutation1: Vec<usize>,
    pub permutation2: Vec<usize>,
    pub permutation3: Vec<usize>,
    pub puncturing: HashMap<usize,bool>
}

impl Permutation{
    // Samples a permutation of the given length, represented as a vector
    // where permutation[i] = j means that the element vector[i] should
    // be mapped to position j after permuting.
    pub fn create(mut rng: &mut ChaCha8Rng, length: usize) -> Self {
        let permutation1 = Self::get_permutation(&mut rng, length);
        let permutation2 = Self::get_permutation(&mut rng, length);
        let permutation3 = Self::get_permutation(&mut rng, length);
        let puncturing = Self::get_puncturing(&mut rng, length);
        assert_eq!(puncturing.len(), length >> 1);
        Self{ permutation1, permutation2, permutation3, puncturing  }
    }

    pub fn get_permutation(mut rng:&mut ChaCha8Rng, length:usize) -> Vec<usize>{
         let mut permutation = Vec::with_capacity(length);

        // Create vector of all indices 0,1,...,length-1.
        let mut rem = vec![0usize; length];

        rem.par_iter_mut().enumerate().for_each(|(i, x)| {
            *x = i;
        });

        // For each position i, randomly choose one of the leftover positions j.
        let mut i = 0;
        while i < length {
            let j = (0..rem.len()).choose(rng).unwrap();
            permutation.push(rem[j] );
            rem.swap_remove(j as usize);
            i = i + 1;
        }
        permutation
    }

    pub fn get_puncturing(mut rng:&mut ChaCha8Rng, length:usize) -> HashMap<usize,bool>{
        let indices = (0..length).choose_multiple(rng, length >> 1);
        let mut res = HashMap::new();
        for i in indices{
            res.insert(i,true);
        }
        return res;
    }

    // Applies permutation to input vector and then punctures.
    fn interleave2<F:BlazeField>(&self, input: Vec<F>) -> Vec<F> {
        let mut new_input = vec![F::zero(); input.len()];
        new_input.par_iter_mut().enumerate().for_each(|(i, mut x)| {
            let mut j = self.permutation2[i];
            *x = input[j];
        });
        new_input 
    }

    fn interleave3<F:BlazeField>(&self, input: Vec<F>) -> Vec<F> {
        let mut new_input = vec![F::zero(); input.len()];
        new_input.par_iter_mut().enumerate().for_each(|(i, mut x)| {
            let mut j = self.permutation3[i];
            *x = input[j];
        });
        new_input 
    }
    // Applies permutation to input vector and then punctures.
    fn puncture<F:BlazeField>(&self, input: Vec<F>) -> Vec<F> {
        let new_input = input.iter().enumerate().filter(|(i,x)| self.puncturing.contains_key(i)).map(|(i,x)| *x).collect::<Vec<_>>();
        assert_eq!(new_input.len(), input.len() >> 1);
        new_input 
    }




    pub fn interleave_long<F:BlazeField>(&self, input: &Vec<Vec<F>>) -> Vec<Vec<F>>{
        let mut new_inputs = Vec::new();
        for vec in input{
            let mut new_input = vec![F::zero(); vec.len()];
            new_input.par_iter_mut().enumerate().for_each(|(i, mut x)| {
                let mut j = self.permutation2[i];
                *x = vec[j];
            });
            new_inputs.push(new_input);
        }
        new_inputs
    }


    // Repeats the input and then applies the permutation.
    fn repeat_interleave<F:BlazeField>(&self, input: Vec<F>, rate: usize) -> Vec<F> {
        let mut new_input = vec![F::zero();input.len() * rate]; 
        let repetition = repetition_code(&input,rate);
        new_input.iter_mut().enumerate().for_each(|(i, mut x)| {
            let mut y = self.permutation1[i];
            *x = repetition[y as usize];
        });
        repetition
    }

        // Repeats the input and then applies the permutation.
    fn repeat_interleave_long<F:BlazeField>(&self, input: &Vec<Vec<F>>, rate: usize) -> Vec<Vec<F>>{
        let mut new_inputs = Vec::new();
        for vec in input{
            let mut new_input = vec![F::zero(); vec.len() * rate];
            new_input.par_iter_mut().enumerate().for_each(|(i, mut x)| {
                let mut y = 1;//((self.permutation[i] / rate) as f64).floor();
                *x = vec[y as usize];
            });
            new_inputs.push(new_input);
        }
        new_inputs
    }
}
    #[test]
    fn test_puncture(){
        type F = Blazeu64;
        let mut rng = ChaCha8Rng::from_entropy();
        let perm = Permutation::create(&mut rng, 1<<15);
        let a = F { value: 8u64 };
        let b = F {value : 16u64}; 
        let input = vec![a;1<<15];
        let now = Instant::now();
        let result = perm.puncture(input);
        println!("puncture {:?}", now.elapsed());
        //println!("output {:?}", result);

    }

pub fn log2_strict(n: usize) -> usize {
    let res = n.trailing_zeros();
    assert!(n.wrapping_shr(res) == 1, "Not a power of two: {n}");
    // Tell the optimizer about the semantics of `log2_strict`. i.e. it can replace `n` with
    // `1 << res` and vice versa.
    res as usize
}

fn serial_accumulator<F:BlazeField>(mut input: &mut Vec<F>) {
    let mut prev_value = F::zero();
    for i in 0..input.len() {
        input[i] = input[i] ^ prev_value;
        prev_value = input[i];
    }
}

pub fn serial_accumulator_long<F:BlazeField>(mut input:&mut Vec<Vec<F>>){
    input.par_iter_mut().for_each(|mut v|{
        serial_accumulator(&mut v);
    });
}


pub fn repetition_code_long<F:BlazeField>(input: &Vec<Vec<F>>, rate: usize) -> Vec<Vec<F>> {
    input.par_iter().map(|v|{
        let mut final_codeword = vec![F::zero(); v.len() * rate];
    //repeat each element "rate" times
        for (i, m) in v.iter().enumerate() {
            for j in 0..rate {
                final_codeword[i * rate + j] = *m;
            }
        }
        return final_codeword;
    }).collect::<Vec<_>>()
}

fn repetition_code<F: BlazeField>(message: &Vec<F>, rate: usize) -> Vec<F> {
    let mut final_codeword = vec![F::zero(); message.len() * rate];
    //repeat each element "rate" times
    for (i, m) in message.iter().enumerate() {
        for j in 0..rate {
            final_codeword[i * rate + j] = *m;
        }
    }
    return final_codeword;
}


#[test]
fn test_rep_code_long(){
    type F = Blazeu64;
    let el1 = Blazeu64{ value: 1};
    let el2 = Blazeu64{ value: 2};
    let el3 = Blazeu64{ value: 3};
    let el4 = Blazeu64{ value: 4};
    let input = vec![vec![el1,el2],vec![el3,el4]];
    assert_eq!(repetition_code_long(&input, 2), vec![vec![el1,el1,el2,el2],vec![el3,el3,el4,el4]]);
}

#[test]
fn test_rep_code(){
    type F = Blazeu64;
    let el1 = Blazeu64{ value: 1};
    let el2 = Blazeu64{ value: 2};
    let el3 = Blazeu64{ value: 3};
    let el4 = Blazeu64{ value: 4};
    let input = vec![el1,el2];
    assert_eq!(repetition_code(&input, 2), vec![el1,el1,el2,el2]);
}
fn parallel_accumulator<F:BlazeField>(mut input: &mut Vec<F>) {
    //upward sweeep
    let size_per_core = input.len() / 8;
    input.par_chunks_mut(size_per_core).for_each(|chunk| {
        for i in 0..log2_strict(size_per_core) {
            for j in 0..size_per_core / (1 << (i + 1)) {
                let mut minichunk = &mut chunk[j * (1 << (i + 1))..(j + 1) * (1 << (i + 1))];
                minichunk[(1 << (i + 1)) - 1] =
                    minichunk[(1 << i) - 1] ^ minichunk[(1 << (i + 1)) - 1];
            }
        }
    });
    //finish upward sweep
    for i in log2_strict(size_per_core)..log2_strict(input.len()) {
        //do a bigger chunk to optimize cores - so large chunk should be input.len()/num_cores
        input.par_chunks_mut(1 << (i + 1)).for_each(|chunk| {
            //now we can do non parallel minichunks on chunk in the usual way
            chunk[(1 << (i + 1)) - 1] = chunk[(1 << i) - 1] ^ chunk[(1 << (i + 1)) - 1];
        });
    }
    //temporary - will optimize putting 0 on front of vector
    let mut zero = vec![F::zero()];
    zero.append(input);
    *input = zero;

    //downward sweep
    for i in (log2_strict(size_per_core)..=log2_strict(input.len() - 1) - 2).rev() {
        input.par_chunks_exact_mut(1 << (i + 1)).for_each(|chunk| {
            chunk[(1 << i)] = chunk[(1 << i)] ^ chunk[0];
        })
    }
    input.par_chunks_exact_mut(size_per_core).for_each(|chunk| {
        for i in (0..log2_strict(size_per_core)).rev() {
            for j in 0..size_per_core / (1 << (i + 1)) {
                let mut minichunk = &mut chunk[j * (1 << (i + 1))..(j + 1) * (1 << (i + 1))];
                minichunk[(1 << i)] = minichunk[(1 << i)] ^ minichunk[0];
            }
        }
    });
    input.remove(0);
}

#[test]
fn test_permutation() {
    let mut rng = ChaCha8Rng::from_entropy();
    let p = Permutation::create(&mut rng, 10);
    println!("permutation {:?}", p.permutation1);
    let mut input = vec![Blazeu64{value:0}, Blazeu64{value:1}, Blazeu64{value:2}, Blazeu64{value:3}, Blazeu64{value:4}, Blazeu64{value:5}, Blazeu64{value:6}, Blazeu64{value:7}, Blazeu64{value:8}, Blazeu64{value:9}];
    let mut input_short = vec![Blazeu64{value:0}, Blazeu64{value:1}, Blazeu64{value:2}, Blazeu64{value:3}, Blazeu64{value: 4}];
    println!("input {:?}", input);
    let permuted_input = p.interleave2(input);
    println!("permutted input (no rep) {:?}", permuted_input);
    assert_eq!(permuted_input.iter().map(|x| x.get_value() as usize).collect::<Vec<_>>(), p.permutation1);
    println!("input {:?}", input_short);
    let permuted_input = p.repeat_interleave(input_short, 2);
    println!("permutted input (after 2 reps) {:?}", permuted_input);
}

#[test]
fn test_permutation_performance() {
    let k = 22;
    let mut rng = ChaCha8Rng::from_entropy();
    let p = Permutation::create(&mut rng, 1 << k);
    let mut input = vec![Blazeu64{ value: 1u64}; 1 << k - 2];
    let now = Instant::now();
    p.repeat_interleave(input, 4);
    println!("repeat 4 times then interleave {:?}", now.elapsed());
}

#[test]
fn test_accumulator() {
    let mut rng = ChaCha8Rng::from_entropy();
  //  let p = Permutation::create(&mut rng, 4 * (1 << 21));
    //println!("perm {:?}", p.permutation);
    let mut input = Blazeu64::rand_vec(1<<21);
    let now = Instant::now();
  //  input = p.repeat_interleave(input, 4);
    parallel_accumulator(&mut input);
    println!("time to accumulate {:?}", now.elapsed());
}

fn compare_accumulators(k: usize) {
    let mut input = vec![Blazeu64{value: 1u64}; 1 << k];
    let now = Instant::now();
    parallel_accumulator(&mut input);
    println!("parallel accumulator {:?} : {:?}", k, now.elapsed());
    let now = Instant::now();
    serial_accumulator(&mut input);
    println!("serial accumulator {:?} : {:?}", k, now.elapsed());
}

#[test]
fn test_accumulator_performance() {
    compare_accumulators(21);
    compare_accumulators(15);
    // compare_accumulators(20);
    // compare_accumulators(25);
    // compare_accumulators(30);
}

pub fn encode_bits<F:BlazeField>(
    message: Vec<F>,
    p1: &Permutation,
    rate: usize,
    mut timer: &mut Duration,
) -> Vec<F> {

    let x = message.len();
    let mut first_round = p1.repeat_interleave(message, rate); // Repeat and interleave.

    assert_eq!(first_round.len(),x*rate);
    serial_accumulator(&mut first_round); // Accumulate
    assert_eq!(first_round.len(),x*rate);
    let mut second_round = p1.interleave2(first_round); // Interleave
    assert_eq!(second_round.len(),x*rate);

    serial_accumulator(&mut second_round); // Accumulate



    second_round
}

pub fn encode_bits_ser<F:BlazeField>(
    message: Vec<F>,
    p: &Permutation,
    rate: usize
) -> Vec<F> {
    let mut first_round = p.repeat_interleave(message, rate); // Repeat and interleave.
    serial_accumulator(&mut first_round); // Accumulate
    let mut second_round = p.interleave2(first_round); // Interleave
    serial_accumulator(&mut second_round); // Accumulate
    let mut third_round = p.interleave3(second_round);
    serial_accumulator(&mut third_round);
    third_round
}
pub fn encode_bits_long<F:BlazeField>(
    message: &Vec<Vec<F>>,
    p1: &Permutation,
    p2: &Permutation,
    rate: usize,
    mut timer: &mut Duration,
) -> Vec<Vec<F>> {

    let x = message[0].len();
    let mut first_round = p1.repeat_interleave_long(message, rate); // Repeat and interleave.

 //   assert_eq!(first_round[0].len(),x*rate);
    serial_accumulator_long(&mut first_round); // Accumulate
 //   assert_eq!(first_round[0].len(),x*rate);
    let mut second_round = p2.interleave_long(&first_round); // Interleave
 //   assert_eq!(second_round[0].len(),x*rate);

    serial_accumulator_long(&mut second_round); // Accumulate


    second_round
}


fn test_encode_bits(k: usize) {
    // Sample permutations.
    let mut rng = ChaCha8Rng::from_entropy();
    let now = Instant::now();
    let mut p1 = Permutation::create(&mut rng, 1 << k);
    let mut p2 = Permutation::create(&mut rng, 1 << k);
    println!("Sampling time for both permutations: {:?}", now.elapsed());

    // Encode one test message.
    let mut test_message64 = Vec::new();
    for i in 0..(1 << k - 2) {
        test_message64.push(Blazeu64{value:i});
    }
    let mut timer = Duration::new(0, 0);
    let codeword = encode_bits(test_message64, &p1, 4, &mut timer);
    println!("Encoding time for one message 64: {:?}", timer)
}

fn test_encode_bits_long_64(k: usize, col_size: usize) {
    // Sample permutations.
    let mut rng = ChaCha8Rng::from_entropy();
    let now = Instant::now();
    let mut p1 = Permutation::create(&mut rng, 1 << k);
    let mut p2 = Permutation::create(&mut rng, 1 << k);
    println!("Sampling time for both permutations: {:?}", now.elapsed());

    // Encode one test message.
    let mut test_message64 = Vec::new();
    for i in 0..col_size{
        test_message64.push(Blazeu64::rand_vec(1 << (k - 2)));
    }
    let mut timer = Duration::new(0, 0);
    let now = Instant::now();
    let codeword = encode_bits_long(&test_message64, &p1, &p2, 4, &mut timer);
    println!("Encoding time for one message 64: {:?}", now.elapsed());
}

fn test_encode_bits512(k: usize) {
    // Sample permutations.
    let mut rng = ChaCha8Rng::from_entropy();
    let now = Instant::now();
    let mut p1 = Permutation::create(&mut rng, 1 << k);
    let mut p2 = Permutation::create(&mut rng, 1 << k);
    println!("Sampling time for both permutations: {:?}", now.elapsed());

    // Encode one test message.
    let mut test_message512 = Blazeu512::rand_vec(1 << (k - 2));
    let mut timer = Duration::new(0, 0);
    let codeword = encode_bits(test_message512, &p1, 4, &mut timer);
    println!("Encoding time for one message 512: {:?}", timer)
}

fn test_encode_bits256(k: usize) {
    // Sample permutations.
    let mut rng = ChaCha8Rng::from_entropy();
    let now = Instant::now();
    let mut p1 = Permutation::create(&mut rng, 1 << k);
    let mut p2 = Permutation::create(&mut rng, 1 << k);
    println!("Sampling time for both permutations: {:?}", now.elapsed());

    // Encode one test message.
    let mut test_message256 = Blazeu256::rand_vec(1 << (k - 2));
    let mut timer = Duration::new(0, 0);
    let codeword = encode_bits(test_message256, &p1, 4, &mut timer);
    println!("Encoding time for one message 256: {:?}", timer)
}

fn test_encode_bits64x8(k: usize) {
    // Sample permutations.
    let mut rng = ChaCha8Rng::from_entropy();
    let now = Instant::now();
    let mut p1 = Permutation::create(&mut rng, 1 << k);
    let mut p2 = Permutation::create(&mut rng, 1 << k);
    println!("Sampling time for both permutations: {:?}", now.elapsed());

    // Encode one test message.
    let mut test_message512 = Blazeu64x8::rand_vec(1 << (k - 2));
    let mut timer = Duration::new(0, 0);
    let codeword = encode_bits(test_message512, &p1, 4, &mut timer);
    println!("Encoding time for one message 64x8: {:?}", timer)
}

#[test]
fn test_encode() {
    test_encode_bits(10);
    test_encode_bits(15);
    test_encode_bits(20);
    test_encode_bits(25);
    test_encode_bits256(10);
    test_encode_bits256(15);
    test_encode_bits256(20);
    test_encode_bits256(25);
    // test_encode_bits(25);
    // test_encode_bits(28);
}

#[test]
fn test_encode_long(){
    test_encode_bits_long_64(21,2);

}



/*
fn accumulator<F: PrimeField>(mut input: &mut Vec<F>) {
    let mut prev_value = F::from(0);
    for i in 0..input.len() {
        input[i] += prev_value;
        prev_value = input[i];
    }
}



fn interleave<F: Copy>(permutation: &Vec<usize>, mut input: &mut Vec<F>) {
    let mut origin_index = 0;
    let mut origin_val = input[origin_index];
    let mut visited_nodes_count = 0;
    while visited_nodes_count < input.len() {
        let dest_val = input[permutation[origin_index]];
        input[permutation[origin_index]] = origin_val;
        origin_val = dest_val;
        origin_index = permutation[origin_index];
        visited_nodes_count += 1;
    }
}

fn repetition_code<F: PrimeField>(message: &Vec<F>, rate: usize) -> Vec<F> {
    let mut final_codeword = vec![F::from(0); message.len() * rate];
    //repeat each element "rate" times
    for (i, m) in message.iter().enumerate() {
        for j in 0..rate {
            final_codeword[i * rate + j] = *m;
        }
    }
    return final_codeword;
}



//good for rate = 1/2, num_concats = 3 or rate = 1/3, num_concats = 2
fn encode<F: PrimeField>(
    message: &Vec<F>,
    permutation: &Vec<usize>,
    rate: usize,
    num_concats: usize,
    mut timer: &mut Duration,
) -> Vec<F> {
    assert_eq!(permutation.len(), message.len());
    //repetition, interleave, accumulate
    let rep_time = Instant::now();
    let mut rep_code = repetition_code(message, rate);
    *timer = *timer + rep_time.elapsed();
    for _ in 0..num_concats {
        let interleave_time = Instant::now();
        interleave(permutation, &mut rep_code);
        *timer = *timer + interleave_time.elapsed();
        let accum_time = Instant::now();
        accumulator(&mut rep_code);
        *timer = *timer + accum_time.elapsed();
    }
    return rep_code;
}



#[cfg(test)]
mod tests {
    use super::*;
    type F = Mersenne61Mont;
    #[test]
    fn test_accumulator() {
        let mut test_vec = vec![F::from(1), F::from(2), F::from(3), F::from(4)];
        accumulator(&mut test_vec);
        assert_eq!(
            test_vec,
            vec![F::from(1), F::from(3), F::from(6), F::from(10)]
        );
    }
    #[test]
    fn test_interleave() {
        let mut test_permutation: Vec<usize> = vec![2, 3, 1, 0]; //0->2, 1 -> 3, 2 -> 1, 3 -> 0 , [X,X,F1,X], [X,F3,F1,X], [F4,F3,F1,F2]
        let mut test_input = vec![F::from(1), F::from(2), F::from(3), F::from(4)]; //
        interleave(&test_permutation, &mut test_input);
        assert_eq!(
            test_input,
            vec![F::from(4), F::from(3), F::from(1), F::from(2)]
        );
    }
    #[test]
    fn test_rep_code() {
        let mut test_vec = vec![F::from(1), F::from(2), F::from(3), F::from(4)];
        let final_codeword = repetition_code(&test_vec, 2);
        assert_eq!(
            final_codeword,
            vec![
                F::from(1),
                F::from(1),
                F::from(2),
                F::from(2),
                F::from(3),
                F::from(3),
                F::from(4),
                F::from(4)
            ]
        );
    }

    const max: u64 = 1 << 25;
    #[test]
    fn test_encode() {
        let mut test_message = Vec::new();
        let mut permutation: Vec<usize> = Vec::new();
        for i in 0..(max) {
            test_message.push(F::from(i));
            permutation.push(((i + 2) % max) as usize);
        }
        let mut timer = Duration::new(0, 0);
        let codeword = encode(&test_message, &permutation, 2, 3, &mut timer);
        println!("timer total {:?} for rate = 1/2, l = 3", timer);
        assert_eq!(codeword.len(), test_message.len() * 2);

        let mut timer = Duration::new(0, 0);
        let codeword = encode(&test_message, &permutation, 3, 2, &mut timer);
        println!("timer total {:?} for rate = 1/3, l = 2", timer);
        assert_eq!(codeword.len(), test_message.len() * 3);

        let mut timer = Duration::new(0, 0);
        let codeword = encode(&test_message, &permutation, 6, 2, &mut timer);
        println!("timer total {:?} for rate = 1/6, l = 2", timer);
        assert_eq!(codeword.len(), test_message.len() * 6);
    }

    #[test]
    fn test_encode_bits() {
        let mut test_message = Vec::new();
        let mut permutation: Vec<usize> = Vec::new();
        for i in 0..(max) {
            test_message.push(i as u32);
            permutation.push((((i as u32) + 2) % (max as u32)) as usize);
        }
        let mut timer = Duration::new(0, 0);
        let codeword = encode_bits(&test_message, &permutation, 2, 3, &mut timer);
        println!("timer bits total {:?} for rate = 1/2, l = 3", timer);
        assert_eq!(codeword.len(), test_message.len() * 2);

        let mut timer = Duration::new(0, 0);
        let codeword = encode_bits(&test_message, &permutation, 3, 2, &mut timer);
        println!("timer bits total {:?} for rate = 1/3, l = 2", timer);
        assert_eq!(codeword.len(), test_message.len() * 3);

        let mut timer = Duration::new(0, 0);
        let codeword = encode_bits(&test_message, &permutation, 6, 2, &mut timer);
        println!("timer bits total {:?} for rate = 1/6, l = 2", timer);
        assert_eq!(codeword.len(), test_message.len() * 6);
    }
}
*/

