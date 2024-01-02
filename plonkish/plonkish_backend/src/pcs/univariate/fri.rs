use crate::piop::sum_check::{
    classic::{ClassicSumCheck, CoefficientsProver},
    eq_xy_eval, SumCheck as _, VirtualPolynomial,
};
use rayon::iter::ParallelBridge;

use crate::{
    pcs::{AdditiveCommitment, Commitment, Evaluation, Point, PolynomialCommitmentScheme},
    poly::{
        univariate::{CoefficientBasis, UnivariatePolynomial},
        Polynomial,
    },
    util::{
        arithmetic::{div_ceil, horner, inner_product, steps, BatchInvert, Field, PrimeField},
        code::{Brakedown, BrakedownSpec, LinearCodes},
        expression::{Expression, Query, Rotation},
        hash::{Hash, Output},
        parallel::{num_threads, parallelize, parallelize_iter},
        transcript::{FieldTranscript, TranscriptRead, TranscriptWrite},
        BigUint, Deserialize, DeserializeOwned, Itertools, Serialize,
    },
    Error,
};
use core::ptr::addr_of;
use ff::BatchInverter;
use rayon::iter::IntoParallelIterator;
use std::{collections::HashMap, iter, ops::Deref, time::Instant};

use plonky2_util::{reverse_bits, reverse_index_bits_in_place};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha12Rng,
};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
    ParallelSlice, ParallelSliceMut,
};
use std::{borrow::Cow, marker::PhantomData, mem::size_of, slice};
type SumCheck<F> = ClassicSumCheck<CoefficientsProver<F>>;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriParams<F: PrimeField> {
    log_rate: usize,
    num_verifier_queries: usize,
    num_vars: usize,
    num_rounds: Option<usize>,
    table_w_weights: Vec<Vec<(F, F)>>,
    table: Vec<Vec<F>>,
    udr_queries: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriProverParams<F: PrimeField> {
    pub log_rate: usize,
    table_w_weights: Vec<Vec<(F, F)>>,
    pub table: Vec<Vec<F>>,
    num_verifier_queries: usize,
    pub num_vars: usize,
    num_rounds: usize,
    udr_queries: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriVerifierParams<F: PrimeField> {
    pub num_vars: usize,
    pub log_rate: usize,
    pub num_verifier_queries: usize,
    num_rounds: usize,
    table_w_weights: Vec<Vec<(F, F)>>,
    udr_queries: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize", deserialize = "F: DeserializeOwned"))]
pub struct FriCommitment<F:PrimeField, H: Hash> {
    pub codeword: Vec<F>,
    pub codeword_tree: Vec<Vec<Output<H>>>,
}

impl<F: PrimeField, H: Hash> FriCommitment<F, H> {
    fn from_root(root: Output<H>) -> Self {
        Self {
            codeword: Vec::new(),
            codeword_tree: vec![vec![root]],
        }
    }
}
impl<F: PrimeField, H: Hash> PartialEq for FriCommitment<F, H> {
    fn eq(&self, other: &Self) -> bool {
        self.codeword.eq(&other.codeword) && self.codeword_tree.eq(&other.codeword_tree)
    }
}

impl<F: PrimeField, H: Hash> Eq for FriCommitment<F, H> {}
#[derive(Debug)]
pub struct Fri<F: PrimeField, H: Hash>(PhantomData<(F, H)>);

impl<F: PrimeField, H: Hash> Clone for Fri<F, H> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<F: PrimeField, H: Hash> AsRef<[Output<H>]> for FriCommitment<F, H> {
    fn as_ref(&self) -> &[Output<H>] {
        let root = &self.codeword_tree[self.codeword_tree.len() - 1][0];
        slice::from_ref(root)
    }
}
impl<F: PrimeField, H: Hash> AdditiveCommitment<F> for FriCommitment<F, H> {
    fn sum_with_scalar<'a>(
        scalars: impl IntoIterator<Item = &'a F> + 'a,
        bases: impl IntoIterator<Item = &'a Self> + 'a,
    ) -> Self {
        let bases = bases.into_iter().collect_vec();

        let scalars = scalars.into_iter().collect_vec();
        let bases = bases.into_iter().collect_vec();

        let mut new_codeword = vec![F::ZERO; bases[0].codeword.len()];
        new_codeword
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, mut c)| {
                for j in 0..bases.len() {
                    *c += *scalars[j] * bases[j].codeword[i];
                }
            });

        let tree = merkelize::<F, H>(&new_codeword);

        Self {
            codeword: new_codeword,
            codeword_tree: tree,
        }
    }
}
impl<F, H> PolynomialCommitmentScheme<F> for Fri<F, H>
where
    F: PrimeField + Serialize + DeserializeOwned,
    H: Hash,
{
    type Param = FriParams<F>;
    type ProverParam = FriProverParams<F>;
    type VerifierParam = FriVerifierParams<F>;
    type Polynomial = UnivariatePolynomial<F, CoefficientBasis>;
    type Commitment = FriCommitment<F, H>;
    type CommitmentChunk = Output<H>;

    fn setup(poly_size: usize, _: usize, rng: impl RngCore) -> Result<Self::Param, Error> {
        let rate = 3;
        let lg_n: usize = rate + log2_strict(poly_size);

        let mut bases = Vec::with_capacity(lg_n);
        let mut base = primitive_root_of_unity::<F>(lg_n);
        bases.push(base);
        for _ in 1..lg_n {
            base = base * base; // base = g^2^_
            bases.push(base);
        }
        let mut root_table = Vec::with_capacity(1 << lg_n);

        for lg_m in 1..=lg_n {
            let half_m = 1 << (lg_m - 1);
            let base = bases[lg_n - lg_m];
            let mut powers_iter = Powers::<F> {
                base: base,
                current: F::ONE,
            };

            for j in 0..half_m.max(2) {
                let el = powers_iter.next().unwrap();
                root_table.push(el);
            }
        }

        let mut weights: Vec<F> = root_table
            .par_iter()
            .map(|el| F::ZERO - *el - *el)
            .collect();

        let mut scratch_space = vec![F::ZERO; weights.len()];
        BatchInverter::invert_with_external_scratch(&mut weights, &mut scratch_space);

        let mut flat_table_w_weights = root_table
            .iter()
            .zip(weights)
            .map(|(el, w)| (*el, w))
            .collect_vec();

        let mut unflattened_table_w_weights = vec![Vec::new(); lg_n];
        let mut unflattened_table = vec![Vec::new(); lg_n];

        let mut level_weights = flat_table_w_weights[0..2].to_vec();
        reverse_index_bits_in_place(&mut level_weights);
        unflattened_table_w_weights[0] = level_weights;

        unflattened_table[0] = root_table[0..2].to_vec();
        for i in 1..lg_n {
            unflattened_table[i] = root_table[(1 << i)..(1 << (i + 1))].to_vec();
            let mut level = flat_table_w_weights[(1 << i)..(1 << (i + 1))].to_vec();
            reverse_index_bits_in_place(&mut level);
            unflattened_table_w_weights[i] = level;
        }

        Ok(FriParams {
            log_rate: rate, 
            num_verifier_queries: 66,
            num_vars: log2_strict(poly_size),
            num_rounds: None, //Some(log2_strict(poly_size) - 1),
            table_w_weights: unflattened_table_w_weights,
            table: unflattened_table,
            udr_queries: 132,
        })
    }
    fn trim(
        param: &Self::Param,
        poly_size: usize,
        batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        let mut rounds = param.num_vars;
        if param.num_rounds.is_some() {
            rounds = param.num_rounds.unwrap();
        }

        Ok((
            FriProverParams {
                log_rate: param.log_rate,
                table_w_weights: param.table_w_weights.clone(),
                table: param.table.clone(),
                num_verifier_queries: param.num_verifier_queries,
                num_vars: param.num_vars,
                num_rounds: rounds,
                udr_queries: param.udr_queries,
            },
            FriVerifierParams {
                num_vars: param.num_vars,
                log_rate: param.log_rate,
                num_verifier_queries: param.num_verifier_queries,
                num_rounds: rounds,
                table_w_weights: param.table_w_weights.clone(),
                udr_queries: param.udr_queries,
            },
        ))
    }

    fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Result<Self::Commitment, Error> {

        let mut commitment =
            evaluate_over_foldable_domain(pp.log_rate, poly.coeffs().to_vec(), &pp.table);

        reverse_index_bits_in_place(&mut commitment);

        let tree = merkelize::<F, H>(&commitment);

        Ok(Self::Commitment {
            codeword: commitment,
            codeword_tree: tree,
        })
    }

    fn batch_commit_and_write<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, Error>
    where
        Self::Polynomial: 'a,
    {
        let comms = Self::batch_commit(pp, polys)?;
        let mut roots = Vec::with_capacity(comms.len());

        comms.iter().for_each(|comm| {
            let root = &comm.codeword_tree[comm.codeword_tree.len() - 1][0];
            roots.push(root);
        });

        transcript.write_commitments(roots).unwrap();
        Ok(comms)
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        let now = Instant::now();
        let polys_vec: Vec<&Self::Polynomial> = polys.into_iter().map(|poly| poly).collect();
        //	println!("now to vec {:?}", now.elapsed().as_millis());
        polys_vec
            .par_iter()
            .map(|poly| {
                let comm = Self::commit(pp, poly);
                comm
            })
            .collect()
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        //construct evaluation codeword
	use std::env;
//	let key = "RAYON_NUM_THREADS";
//	env::set_var(key, "8");	

	open_helper(pp,poly,comm,point,eval,transcript).0
    }

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {

        let polys = polys.into_iter().collect_vec();
        let comms = comms.into_iter().collect_vec();

        Ok(())
    }

    fn read_commitments(
        _: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        let roots = transcript.read_commitments(num_polys).unwrap();

        Ok(roots
            .iter()
            .map(|r| FriCommitment::from_root(r.clone()))
            .collect_vec())
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
	verify_helper(vp,comm,point,eval,transcript).0
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        let comms = comms.into_iter().collect_vec();
        Ok(())
    }
}

pub fn evaluate_over_foldable_domain<F: PrimeField>(
    log_rate: usize,
    mut coeffs: Vec<F>,
    table: &Vec<Vec<F>>,
) -> Vec<F> {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let k = coeffs.len();
    //    println!("k {:?}", k);
    let logk = log2_strict(k);
    let cl = 1 << (logk + log_rate);
    let rate = 1 << log_rate;
    let mut coeffs_with_rep = Vec::with_capacity(cl);
    for i in 0..cl {
        coeffs_with_rep.push(F::ZERO);
    }

    let now = Instant::now();
    for i in 0..k {
        for j in 0..rate {
            coeffs_with_rep[i * rate + j] = coeffs[i];
        }
    }

    let mut chunk_size = rate;
    for i in 0..logk {
        let level = &table[i + log_rate];
        chunk_size = chunk_size << 1;
        assert_eq!(level.len(), chunk_size >> 1);
        <Vec<F> as AsMut<[F]>>::as_mut(&mut coeffs_with_rep)
            .par_chunks_mut(chunk_size)
            .for_each(|chunk| {
                let half_chunk = chunk_size >> 1;
                for j in half_chunk..chunk_size {
                    let rhs = chunk[j] * level[j - half_chunk];
                    chunk[j] = chunk[j - half_chunk] - rhs;
                    chunk[j - half_chunk] = chunk[j - half_chunk] + rhs;
                }
            });
    }
    coeffs_with_rep
}

fn interpolate_over_boolean_hypercube_with_copy<F: PrimeField>(evals: &Vec<F>) -> (Vec<F>, Vec<F>) {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let n = log2_strict(evals.len());
    let mut coeffs = vec![F::ZERO; evals.len()];
    let mut new_evals = vec![F::ZERO; evals.len()];

    let mut j = 0;
    while (j < coeffs.len()) {
        new_evals[j] = evals[j];
        new_evals[j + 1] = evals[j + 1];

        coeffs[j + 1] = evals[j + 1] - evals[j];
        coeffs[j] = evals[j];
        j += 2
    }

    for i in 2..n + 1 {
        let chunk_size = 1 << i;
        coeffs.par_chunks_mut(chunk_size).for_each(|chunk| {
            let half_chunk = chunk_size >> 1;
            for j in half_chunk..chunk_size {
                chunk[j] = chunk[j] - chunk[j - half_chunk];
            }
        });
    }

    (coeffs, new_evals)
}

//helper function
fn rand_vec<F: PrimeField>(size: usize, mut rng: &mut ChaCha12Rng) -> Vec<F> {
    (0..size).map(|_| F::random(&mut rng)).collect()
}
fn rand_chacha<F: PrimeField>(mut rng: &mut ChaCha12Rng) -> F {
    let bytes = (F::NUM_BITS as usize).next_power_of_two() / 8;
    let mut dest: Vec<u8> = vec![0u8; bytes];
    rng.fill_bytes(&mut dest);
    from_raw_bytes::<F>(&dest)
}

pub fn log2_strict(n: usize) -> usize {
    let res = n.trailing_zeros();
    assert!(n.wrapping_shr(res) == 1, "Not a power of two: {n}");
    // Tell the optimizer about the semantics of `log2_strict`. i.e. it can replace `n` with
    // `1 << res` and vice versa.

    res as usize
}

fn merkelize<F: PrimeField, H: Hash>(values: &Vec<F>) -> Vec<Vec<Output<H>>> {
    let log_v = log2_strict(values.len());
    let mut tree = Vec::with_capacity(log_v);
    let mut hashes = vec![Output::<H>::default(); (values.len() >> 1)];
    let method1 = Instant::now();
    hashes.par_iter_mut().enumerate().for_each(|(i, mut hash)| {
        let mut hasher = H::new();
        hasher.update_field_element(&values[i + i]);
        hasher.update_field_element(&values[i + i + 1]);
        *hash = hasher.finalize_fixed();
    });

    tree.push(hashes);

    let now = Instant::now();
    for i in 1..(log_v) {
        let oracle = tree[i - 1]
            .par_chunks_exact(2)
            .map(|ys| {
                let mut hasher = H::new();
                let mut hash = Output::<H>::default();
                hasher.update(&ys[0]);
                hasher.update(&ys[1]);
                hasher.finalize_fixed()
            })
            .collect::<Vec<_>>();

        tree.push(oracle);
    }
    tree
}

fn basefold_one_round_by_interpolation_weights<F: PrimeField>(
    table: &Vec<Vec<(F, F)>>,
    table_offset: usize,
    values: &Vec<F>,
    challenge: F,
) -> Vec<F> {
    let level = &table[table.len() - 1 - table_offset];

    values
        .par_chunks_exact(2)
        .enumerate()
        .map(|(i, ys)| {
            interpolate2_weights::<F>(
                [(level[i].0, ys[0]), (-(level[i].0), ys[1])],
                level[i].1,
                challenge,
            )
        })
        .collect::<Vec<_>>()
}

fn basefold_get_query<F: PrimeField>(
    first_oracle: &Vec<F>,
    oracles: &Vec<Vec<F>>,
    mut x_index: usize,
) -> (Vec<(F, F)>, Vec<usize>) {
    let mut queries = Vec::with_capacity(oracles.len() + 1);
    let mut indices = Vec::with_capacity(oracles.len() + 1);

    let mut p0 = x_index;
    let mut p1 = x_index ^ 1;

    if (p1 < p0) {
        p0 = x_index ^ 1;
        p1 = x_index;
    }
    queries.push((first_oracle[p0], first_oracle[p1]));
    indices.push(p0);
    x_index >>= 1;

    for oracle in oracles {
        let mut p0 = x_index;
        let mut p1 = x_index ^ 1;
        if (p1 < p0) {
            p0 = x_index ^ 1;
            p1 = x_index;
        }
        queries.push((oracle[p0], oracle[p1]));
        indices.push(p0);
        x_index >>= 1;
    }

    return (queries, indices);
}

fn get_merkle_path<H: Hash, F: PrimeField>(
    tree: &Vec<Vec<Output<H>>>,
    mut x_index: usize,
    root: bool,
) -> Vec<(Output<H>, Output<H>)> {
    let mut queries = Vec::with_capacity(tree.len());
    x_index >>= 1;
    for oracle in tree {
        let mut p0 = x_index;
        let mut p1 = x_index ^ 1;
        if (p1 < p0) {
            p0 = x_index ^ 1;
            p1 = x_index;
        }
        if (oracle.len() == 1) {
            if (root) {
                queries.push((oracle[0].clone(), oracle[0].clone()));
            }
            break;
        }
        queries.push((oracle[p0].clone(), oracle[p1].clone()));
        x_index >>= 1;
    }

    return queries;
}

fn write_merkle_path<H: Hash, F: PrimeField>(
    tree: &Vec<Vec<Output<H>>>,
    mut x_index: usize,
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
) {
    x_index >>= 1;
    for oracle in tree {
        let mut p0 = x_index;
        let mut p1 = x_index ^ 1;
        if (p1 < p0) {
            p0 = x_index ^ 1;
            p1 = x_index;
        }
        if (oracle.len() == 1) {
            //	    transcript.write_commitment(&oracle[0]);
            break;
        }
        transcript.write_commitment(&oracle[p0]);
        transcript.write_commitment(&oracle[p1]);
        x_index >>= 1;
    }
}

fn authenticate_merkle_path<H: Hash, F: PrimeField>(
    path: &Vec<Vec<Output<H>>>,
    leaves: (F, F),
    mut x_index: usize,
) {
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    hasher.update_field_element(&leaves.0);
    hasher.update_field_element(&leaves.1);
    hasher.finalize_into_reset(&mut hash);

    assert_eq!(hash, path[0][(x_index >> 1) % 2]);
    x_index >>= 1;
    for i in 0..path.len() {
        if (i + 1 == path.len()) {
            break;
        }
        let mut hasher = H::new();
        let mut hash = Output::<H>::default();
        hasher.update(&path[i][0]);
        hasher.update(&path[i][1]);
        hasher.finalize_into_reset(&mut hash);

        assert_eq!(hash, path[i + 1][(x_index >> 1) % 2]);
        x_index >>= 1;
    }
}

fn authenticate_merkle_path_root<H: Hash, F: PrimeField>(
    path: &Vec<Vec<Output<H>>>,
    leaves: (F, F),
    mut x_index: usize,
    root: &Output<H>,
) {
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    hasher.update_field_element(&leaves.0);
    hasher.update_field_element(&leaves.1);
    hasher.finalize_into_reset(&mut hash);

    assert_eq!(hash, path[0][(x_index >> 1) % 2]);
    x_index >>= 1;
    for i in 0..path.len() - 1 {
        let mut hasher = H::new();
        let mut hash = Output::<H>::default();
        hasher.update(&path[i][0]);
        hasher.update(&path[i][1]);
        hasher.finalize_into_reset(&mut hash);

        assert_eq!(hash, path[i + 1][(x_index >> 1) % 2]);
        x_index >>= 1;
    }
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    hasher.update(&path[path.len() - 1][0]);
    hasher.update(&path[path.len() - 1][1]);
    hasher.finalize_into_reset(&mut hash);
    assert_eq!(&hash, root);
}

pub fn interpolate2_weights<F: PrimeField>(points: [(F, F); 2], weight: F, x: F) -> F {
    // a0 -> a1
    // b0 -> b1
    // x  -> a1 + (x-a0)*(b1-a1)/(b0-a0)
    let (a0, a1) = points[0];
    let (b0, b1) = points[1];
    //    assert_ne!(a0, b0);
    a1 + (x - a0) * (b1 - a1) * weight
}

pub fn query_point<F: PrimeField>(
    final_block_length: usize,
    block_length: usize,
    eval_index: usize,
    level: usize,
    base: F,
) -> F {
    let lg_n = log2_strict(final_block_length);

    let level_index = eval_index % (block_length);
/*
    let mut powers_iter = Powers::<F> {
        base: base,
        current: F::ONE,
    };
*/
    let mut el = exp_u64(&base,(level_index % (block_length >> 1)) as u64); //F::ONE;


/*
    for j in 0..=(level_index % (block_length >> 1)) {
        el = powers_iter.next().unwrap();
    }
*/



    if level_index >= (block_length >> 1) {
        el = -F::ONE * el;
    }

    return el;
}

pub fn interpolate2<F: PrimeField>(points: [(F, F); 2], x: F) -> F {
    // a0 -> a1
    // b0 -> b1
    // x  -> a1 + (x-a0)*(b1-a1)/(b0-a0)
    let (a0, a1) = points[0];
    let (b0, b1) = points[1];
    assert_ne!(a0, b0);
    a1 + (x - a0) * (b1 - a1) * (b0 - a0).invert().unwrap()
}

fn degree_2_zero_plus_one<F: PrimeField>(poly: &Vec<F>) -> F {
    poly[0] + poly[0] + poly[1] + poly[2]
}

fn degree_2_eval<F: PrimeField>(poly: &Vec<F>, point: F) -> F {
    poly[0] + point * poly[1] + point * point * poly[2]
}

pub fn interpolate_over_boolean_hypercube<F: PrimeField>(mut evals: Vec<F>) -> Vec<F> {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    //    println!("before this");
    let n = log2_strict(evals.len());
    for i in 1..n + 1 {
        let chunk_size = 1 << i;
        evals.par_chunks_mut(chunk_size).for_each(|chunk| {
            let half_chunk = chunk_size >> 1;
            for j in half_chunk..chunk_size {
                chunk[j] = chunk[j] - chunk[j - half_chunk];
            }
        });
    }
    reverse_index_bits_in_place(&mut evals);
    evals
}

pub fn multilinear_evaluation_ztoa<F: PrimeField>(poly: &mut Vec<F>, point: &Vec<F>) {
    let n = log2_strict(poly.len());
    //    assert_eq!(point.len(),n);
    for p in point {
        poly.par_chunks_mut(2).for_each(|chunk| {
            chunk[0] = chunk[0] + *p * chunk[1];
            chunk[1] = chunk[0];
        });
        poly.dedup();
    }
}
#[test]
fn bench_multilinear_eval() {
    use crate::util::ff_255::ff255::Ft255;
    for i in 10..26 {
        let mut rng = ChaCha12Rng::from_entropy();
        let pow = 1 << i;
        let mut poly = rand_vec::<Ft255>(pow, &mut rng);
        let point = rand_vec::<Ft255>(i, &mut rng);
        let now = Instant::now();
        multilinear_evaluation_ztoa(&mut poly, &point);
        println!(
            "time for multilinear eval degree i {:?} : {:?}",
            i,
            now.elapsed().as_millis()
        );
    }
}
fn from_raw_bytes<F: PrimeField>(bytes: &Vec<u8>) -> F {
    let mut res = F::ZERO;
    bytes.into_iter().for_each(|b| {
        res += F::from(u64::from(*b));
    });
    res
}

#[cfg(test)]
mod test {
    use crate::{
        pcs::{
            univariate::{fri::Fri, kzg::UnivariateKzg},
            Evaluation, PolynomialCommitmentScheme,
        },
        util::{
            chain,
            transcript::{
                FieldTranscript, FieldTranscriptRead, FieldTranscriptWrite, InMemoryTranscript,
                Keccak256Transcript,
            },
            Itertools,
        },
    };
    use blake2::{digest::FixedOutputReset, Blake2s256};
    use halo2_curves::bn256::{Bn256, Fr};
    use rand::{rngs::OsRng, Rng};
    use std::{iter, time::Instant};
    type Pcs = Fri<Fr, Blake2s256>;
    type Polynomial = <Pcs as PolynomialCommitmentScheme<Fr>>::Polynomial;

    #[test]
    fn commit_open_verify() {
        for k in 10..25{
            //            println!("k {:?}", k);
            // Setup
            let (pp, vp) = {
                let mut rng = OsRng;
                let poly_size = 1 << k;
                let param = Pcs::setup(poly_size, 1, &mut rng).unwrap();
                Pcs::trim(&param, poly_size, 1).unwrap()
            };
            // Commit and open
            let proof = {
                let mut transcript = Keccak256Transcript::default();
                let poly = Polynomial::rand((1 << k) - 1, OsRng);
                let now = Instant::now();

                let comm = Pcs::commit_and_write(&pp, &poly, &mut transcript).unwrap();
                let point = transcript.squeeze_challenge();
                let eval = poly.evaluate(&point);
                transcript.write_field_element(&eval).unwrap();

                Pcs::open(&pp, &poly, &comm, &point, &eval, &mut transcript).unwrap();
                println!("total proof time {:?}", now.elapsed());

                transcript.into_proof()
            };
            // Verify
            let result = {
                let mut transcript = Keccak256Transcript::from_proof((), proof.as_slice());
                let now = Instant::now();
                let v = Pcs::verify(
                    &vp,
                    &Pcs::read_commitment(&vp, &mut transcript).unwrap(),
                    &transcript.squeeze_challenge(),
                    &transcript.read_field_element().unwrap(),
                    &mut transcript,
                );
                //                println!("verify {:?}", now.elapsed());
                v
            };
            assert_eq!(result, Ok(()));
        }
    }
}
fn reed_solomon_into<F: Field>(input: &[F], mut target: impl AsMut<[F]>) {
    target
        .as_mut()
        .iter_mut()
        .zip(steps(F::ONE))
        .for_each(|(target, x)| *target = horner(input, &x));
}

fn virtual_open<F: PrimeField>(
    num_vars: usize,
    num_rounds: usize,
    last_oracle: &Vec<F>,
    challenges: &mut Vec<F>,
    table: &Vec<Vec<(F, F)>>,
) {
    let mut rng = ChaCha12Rng::from_entropy();
    let rounds = num_vars - num_rounds;

    let mut oracles = Vec::with_capacity(rounds);
    let mut new_oracle = last_oracle;
    for round in 0..rounds {
        let challenge: F = rand_chacha(&mut rng);
        challenges.push(challenge);
        oracles.push(basefold_one_round_by_interpolation_weights::<F>(
            &table,
            round + num_rounds,
            &new_oracle,
            challenge,
        ));
        new_oracle = &oracles[round];
    }

    let mut no = new_oracle.clone();
    no.dedup();
    assert_eq!(no.len(), 1);
}
//outputs (trees, oracles, eval)
fn commit_phase<F: PrimeField, H: Hash>(
    point: &Point<F, UnivariatePolynomial<F, CoefficientBasis>>,
    comm: &FriCommitment<F, H>,
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
    num_vars: usize,
    num_rounds: usize,
    table_w_weights: &Vec<Vec<(F, F)>>,
) -> (Vec<Vec<Vec<Output<H>>>>, Vec<Vec<F>>) {
    let mut oracles = Vec::with_capacity(num_vars);

    let mut trees = Vec::with_capacity(num_vars);

    let mut new_tree = &comm.codeword_tree;
    let mut root = new_tree[new_tree.len() - 1][0].clone();
    let mut new_oracle = &comm.codeword;

    let num_rounds = num_rounds;

    for i in 0..(num_rounds) {
        transcript.write_commitment(&root).unwrap();
        let challenge: F = transcript.squeeze_challenge();

        oracles.push(basefold_one_round_by_interpolation_weights::<F>(
            &table_w_weights,
            i,
            new_oracle,
            challenge,
        ));

        new_oracle = &oracles[i];
        trees.push(merkelize::<F, H>(&new_oracle));
        root = trees[i][trees[i].len() - 1][0].clone();
    }

    transcript.write_commitment(&root).unwrap();
    return (trees, oracles);
}

fn query_phase<F: PrimeField, H: Hash>(
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
    comm: &FriCommitment<F, H>,
    oracles: &Vec<Vec<F>>,
    num_verifier_queries: usize,
) -> (Vec<(Vec<(F, F)>, Vec<usize>)>, Vec<usize>) {
    let mut queries = transcript.squeeze_challenges(num_verifier_queries);

    let queries_usize: Vec<usize> = queries
        .iter()
        .map(|x_index| {
            let x_rep = (*x_index).to_repr();
            let mut x: &[u8] = x_rep.as_ref();
            let (int_bytes, rest) = x.split_at(std::mem::size_of::<u32>());
            let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
            ((x_int as usize) % comm.codeword.len()).into()
        })
        .collect_vec();

    (
        queries_usize
            .par_iter()
            .map(|x_index| {
                return basefold_get_query::<F>(&comm.codeword, &oracles, *x_index);
            })
            .collect(),
        queries_usize,
    )
}

fn get_query_indices<F: PrimeField>(rand_queries: &Vec<F>, codeword_len: usize) -> Vec<usize> {
    rand_queries
        .iter()
        .map(|x_index| {
            let x_rep = (*x_index).to_repr();
            let mut x: &[u8] = x_rep.as_ref();
            let (int_bytes, rest) = x.split_at(std::mem::size_of::<u32>());
            let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
            ((x_int as usize) % codeword_len).into()
        })
        .collect_vec()
}

fn query_top_level<F: PrimeField, H: Hash>(
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
    comm: &FriCommitment<F, H>,
    queries_usize: &Vec<usize>,
) -> (Vec<(F, F)>, Vec<Vec<(Output<H>, Output<H>)>>) {
    let mut queried_els = Vec::with_capacity(queries_usize.len());
    let mut paths = Vec::with_capacity(queries_usize.len());
    queries_usize.into_iter().for_each(|x_index| {
        let mut p0 = *x_index;
        let mut p1 = *x_index ^ 1;

        if (p1 < p0) {
            p0 = *x_index ^ 1;
            p1 = *x_index;
        }
        queried_els.push((comm.codeword[p0], comm.codeword[p1]));
        paths.push(get_merkle_path::<H, F>(&comm.codeword_tree, *x_index, true));
    });
    return (queried_els, paths);
}

fn verifier_query_phase<F: PrimeField, H: Hash>(
    query_challenges: &Vec<F>,
    query_merkle_paths: &Vec<Vec<Vec<Vec<Output<H>>>>>,
    fold_challenges: &Vec<F>,
    queries: &Vec<Vec<&[F]>>,
    num_rounds: usize,
    num_vars: usize,
    log_rate: usize,
    roots: &Vec<Output<H>>,
    eval: &F,
) -> Vec<usize> {
    let n = (1 << (num_vars + log_rate));
    let lg_n = num_vars + log_rate;
    let mut queries_usize: Vec<usize> = query_challenges
        .par_iter()
        .map(|x_index| {
            let x_repr = (*x_index).to_repr();
            let mut x: &[u8] = x_repr.as_ref();
            let (int_bytes, rest) = x.split_at(std::mem::size_of::<u32>());
            let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
            ((x_int as usize) % n).into()
        })
        .collect();


    let mut bases = Vec::with_capacity(lg_n);
    let mut base = primitive_root_of_unity::<F>(lg_n);
    bases.push(base);

    for _ in 1..lg_n {
        base = base * base; // base = g^2^_
        bases.push(base);
    }

    queries_usize
        .par_iter_mut()
        .enumerate()
        .for_each(|(qi, query_index)| {
            let mut cur_index = *query_index;
            let mut cur_queries = &queries[qi];

            for i in 0..num_rounds {
                let temp = cur_index;
                let mut other_index = cur_index ^ 1;
                if (other_index < cur_index) {
                    cur_index = other_index;
                    other_index = temp;
                }

                assert_eq!(cur_index % 2, 0);

                let ri0 = reverse_bits(cur_index, num_vars + log_rate - i);
                let ri1 = reverse_bits(other_index, num_vars + log_rate - i);

                let now = Instant::now();

                let x0 = query_point(
                    1 << (num_vars + log_rate),
                    1 << (num_vars + log_rate - i),
                    ri0,
                    num_vars + log_rate - i - 1,
                    bases[i],
                );
		/*
                let x1 = query_point(
                    1 << (num_vars + log_rate),
                    1 << (num_vars + log_rate - i),
                    ri1,
                    num_vars + log_rate - i - 1,
                    bases[i],
                );*/
		let x1 = -x0;
                assert_eq!(x0, -F::ONE * x1);
                //                println!("query point {:?}", now.elapsed());
                let res = interpolate2(
                    [(x0, cur_queries[i][0]), (x1, cur_queries[i][1])],
                    fold_challenges[i],
                );

                assert_eq!(res, cur_queries[i + 1][(cur_index >> 1) % 2]);

                authenticate_merkle_path_root::<H, F>(
                    &query_merkle_paths[qi][i],
                    (cur_queries[i][0], cur_queries[i][1]),
                    cur_index,
                    &roots[i],
                );

                cur_index >>= 1;
            }
        });

    return queries_usize;
}
fn primitive_root_of_unity<F: PrimeField>(n_log: usize) -> F {
    assert!(n_log <= (F::S as usize));
    let base = F::ROOT_OF_UNITY;
    exp_power_of_2(base, (F::S as usize) - n_log)
}
fn exp_power_of_2<F: PrimeField>(el: F, power_log: usize) -> F {
    let mut res = el;
    for _ in 0..power_log {
        res = el * el;
    }
    res
}
fn exp_u64<F:Field>(el:&F, power: u64) -> F {
  let mut current = *el;
  let mut product = F::ONE;
  for j in 0..bits_u64(power) {
    if (power >> j & 1) != 0 {
       product *= current;
    }
    current = current * current;
  }
  product
}

pub fn bits_u64(n: u64) -> usize {
    (64 - n.leading_zeros()) as usize
}

pub struct Powers<F: Field> {
    base: F,
    current: F,
}

impl<F: Field> Iterator for Powers<F> {
    type Item = F;

    fn next(&mut self) -> Option<F> {
        let result = self.current;
        self.current *= self.base;
        Some(result)
    }
}


//return ((leaf1,leaf2),path), where leaves are queries from codewords
fn query_codeword<F: PrimeField, H: Hash>(
    query: &usize,
    codeword: &Vec<F>,
    codeword_tree: &Vec<Vec<Output<H>>>,
) -> ((F, F), Vec<(Output<H>, Output<H>)>) {
    let mut p0 = *query;
    let temp = p0;
    let mut p1 = p0 ^ 1;
    if (p1 < p0) {
        p0 = p1;
        p1 = temp;
    }
    return (
        (codeword[p0], codeword[p1]),
        get_merkle_path::<H, F>(&codeword_tree, *query, true),
    );
}
pub fn open_helper<F:PrimeField,H:Hash>(
    pp:&FriProverParams<F>,
    poly: &UnivariatePolynomial<F,CoefficientBasis>,
    comm: &FriCommitment<F,H>,
    point: &F,
    eval: &F,
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
) -> (Result<(), Error>, (Vec<(Vec<(F, F)>, Vec<usize>)>, Vec<usize>)) {
    //construct evaluation codeword
    let lg_n = log2_strict(comm.codeword.len());
    let mut denominator = Vec::new();
    let mut numerator = Vec::new();
    let last_level = &pp.table_w_weights[pp.table_w_weights.len() - 1];

    let mut d_pointer = 0;
    let sim_domain_point = F::ONE;
    let now = Instant::now();

    for j in 0..comm.codeword.len() {
        let mut x: F = last_level[d_pointer].0;
        if j % 2 != 0 {
            d_pointer = d_pointer + 1;
            x = -x;
        }
        denominator.push(sim_domain_point - point); //replace sim_domain_point with actual domain point
        numerator.push(comm.codeword[j] - eval);
    }

    //batch invert denominators
    let mut scratch_space = vec![F::ZERO; denominator.len()];
    BatchInverter::invert_with_external_scratch(&mut denominator, &mut scratch_space);

    let mut evaluation_codeword = vec![F::ZERO; comm.codeword.len()];
    //multiply numerators and inverted denominators
    evaluation_codeword
        .par_iter_mut()
        .enumerate()
        .for_each(|(j, c)| {
            *c = numerator[j] * denominator[j];
        });
    let m = Instant::now();
    let evaluation_tree = merkelize::<F, H>(&evaluation_codeword);
    //	println!("merkle tree {:?}", m.elapsed());
    //	println!("extra overhead {:?}", now.elapsed());

    let evaluation_commitment = FriCommitment {
        codeword: evaluation_codeword,
        codeword_tree: evaluation_tree,
    };

    let cp = Instant::now();
    let (trees, mut oracles) = commit_phase::<F, H>(
        &point,
        &evaluation_commitment,
        transcript,
        pp.num_vars,
        pp.num_rounds,
        &pp.table_w_weights,
    );
    //	println!("commit phase {:?}", cp.elapsed());
    let (queried_els, queries_usize) = query_phase(
        transcript,
        &evaluation_commitment,
        &oracles,
        pp.num_verifier_queries,
    );

    // a proof consists of roots, merkle paths, query paths,  eval, and final oracle
    transcript.write_field_element(&eval); //write eval

    //write final oracle
    let mut final_oracle = oracles.pop().unwrap();
    transcript.write_field_elements(&final_oracle);

    //write query paths
    queried_els
        .iter()
        .map(|q| &q.0)
        .flatten()
        .for_each(|query| {
            transcript.write_field_element(&query.0);
            transcript.write_field_element(&query.1);
        });

    //write merkle paths
    queried_els.iter().for_each(|query| {
        let indices = &query.1;
        indices.into_iter().enumerate().for_each(|(i, q)| {
            if (i == 0) {
                write_merkle_path::<H, F>(&evaluation_commitment.codeword_tree, *q, transcript);
            } else {
                write_merkle_path::<H, F>(&trees[i - 1], *q, transcript);
            }
        })
    });

    let ov = Instant::now();
    //query corresponding points in original commitment
    let mut corresponding_points = Vec::new();
    let mut corresponding_paths = Vec::new();
    for query in &queries_usize {
        let res = query_codeword::<F, H>(query, &comm.codeword, &comm.codeword_tree);
        corresponding_points.push(res.0);
        corresponding_paths.push(res.1);
    }

    //write corresponding queries
    corresponding_points.iter().for_each(|query| {
        transcript.write_field_element(&query.0);
        transcript.write_field_element(&query.1);
    });

    //write corresponding paths
    corresponding_paths.iter().flatten().for_each(|(h1, h2)| {
        transcript.write_commitment(h1);
        transcript.write_commitment(h2);
    });
    //query extra points in commitment and evaluation commitment (as this needs to be checked within unique decoding radius
    let remaining_queries = pp.udr_queries.checked_sub(pp.num_verifier_queries);
    let (
        mut queries_usize,
        mut eval_queried_els,
        mut eval_paths,
        mut comm_queried_els,
        mut comm_paths,
    ) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    if let Some(a) = remaining_queries {
        let rand_queries = transcript.squeeze_challenges(a);
        queries_usize = get_query_indices(&rand_queries, comm.codeword.len());
        (eval_queried_els, eval_paths) =
            query_top_level(transcript, &evaluation_commitment, &queries_usize);
        (comm_queried_els, comm_paths) = query_top_level(transcript, &comm, &queries_usize);
    }

    //write remaining queries
    eval_queried_els.iter().for_each(|query| {
        transcript.write_field_element(&query.0);
        transcript.write_field_element(&query.1);
    });

    comm_queried_els.iter().for_each(|query| {
        transcript.write_field_element(&query.0);
        transcript.write_field_element(&query.1);
    });

    //write remaining paths
    eval_paths.iter().flatten().for_each(|(h1, h2)| {
        transcript.write_commitment(h1);
        transcript.write_commitment(h2);
    });

    comm_paths.iter().flatten().for_each(|(h1, h2)| {
        transcript.write_commitment(h1);
        transcript.write_commitment(h2);
    });

    //	println!("additional overhead {:?}", ov.elapsed());
    (Ok(()),(queried_els,queries_usize))
}

pub fn verify_helper<F:PrimeField,H:Hash>(
    vp:&FriVerifierParams<F>,
    comm: &FriCommitment<F,H>,
    point: &F,
    eval: &F,
    transcript: &mut impl TranscriptRead<Output<H>, F>,
) -> (Result<(), Error>, Vec<usize>) {
    //construct evaluation codeword
        let field_size = 256;
        let n = (1 << (vp.num_vars + vp.log_rate));
        //read first $(num_var - 1) commitments

        let mut fold_challenges: Vec<F> = Vec::with_capacity(vp.num_vars);
        let mut size = 0;
        let mut roots = Vec::new();
        for i in 0..vp.num_rounds {
            roots.push(transcript.read_commitment().unwrap());
            fold_challenges.push(transcript.squeeze_challenge());
        }
        size = size + 256 * vp.num_rounds;
        //read last commitment
        transcript.read_commitment().unwrap();

        let mut query_challenges = transcript.squeeze_challenges(vp.num_verifier_queries);
        //read eval

        let eval = &transcript.read_field_element().unwrap(); //do not need eval in proof

        //read final oracle
        let mut final_oracle = transcript
            .read_field_elements(1 << (vp.num_vars - vp.num_rounds + vp.log_rate))
            .unwrap();

        size = size + field_size * final_oracle.len();
        //read query paths
        let num_queries = vp.num_verifier_queries * 2 * (vp.num_rounds + 1);

        let all_qs = transcript.read_field_elements(num_queries).unwrap();

        size = size + (num_queries - 2) * field_size;

        let i_qs = all_qs.chunks((vp.num_rounds + 1) * 2).collect_vec();

        assert_eq!(i_qs.len(), vp.num_verifier_queries);

        let mut queries = i_qs.iter().map(|q| q.chunks(2).collect_vec()).collect_vec();

        assert_eq!(queries.len(), vp.num_verifier_queries);

        //read merkle paths

        let mut query_merkle_paths: Vec<Vec<Vec<Vec<Output<H>>>>> =
            Vec::with_capacity(vp.num_verifier_queries);
        let query_merkle_paths: Vec<Vec<Vec<Vec<Output<H>>>>> = (0..vp.num_verifier_queries)
            .into_iter()
            .map(|i| {
                let mut merkle_paths: Vec<Vec<Vec<Output<H>>>> =
                    Vec::with_capacity(vp.num_rounds + 1);
                for round in 0..(vp.num_rounds + 1) {
                    let mut merkle_path: Vec<Output<H>> = transcript
                        .read_commitments(2 * (vp.num_vars - round + vp.log_rate - 1))
                        .unwrap();
                    size = size + 256 * (2 * (vp.num_vars - round + vp.log_rate - 1));

                    let chunked_path: Vec<Vec<Output<H>>> =
                        merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();

                    merkle_paths.push(chunked_path);
                }
                merkle_paths
            })
            .collect();

        let mut corresponding_queries = Vec::with_capacity(vp.num_verifier_queries);
        for i in 0..vp.num_verifier_queries {
            corresponding_queries.push(transcript.read_field_elements(2).unwrap());
            size = size + 2 * field_size;
        }

        //read corresponding queries and paths
        let mut corresponding_paths = Vec::with_capacity(vp.num_verifier_queries);
        for i in 0..vp.num_verifier_queries {
            let merkle_path = transcript
                .read_commitments(2 * (vp.num_vars + vp.log_rate))
                .unwrap();
            size = size + 2 * (vp.num_vars + vp.log_rate) * 256;
            let chunked_path = merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();
            corresponding_paths.push(chunked_path);
        }
        let now = Instant::now();
        let queries_usize = verifier_query_phase::<F, H>(
            &query_challenges,
            &query_merkle_paths,
            &fold_challenges,
            &queries,
            vp.num_rounds,
            vp.num_vars,
            vp.log_rate,
            &roots,
            &eval,
        );
        //        println!("now {:?}", now.elapsed().as_millis());
        //verify corresponding paths
        for i in 0..corresponding_paths.len() {
            authenticate_merkle_path::<H, F>(
                &corresponding_paths[i],
                (corresponding_queries[i][0], corresponding_queries[i][1]),
                queries_usize[i],
            );
        }
        let now = Instant::now();
        //verify corresponding queries are related correctly

        for (i, query) in queries.iter().enumerate() {
            let sim_query_0 =
                (corresponding_queries[i][0] - eval) * (F::ONE - point).invert().unwrap();
            let sim_query_1 =
                (corresponding_queries[i][1] - eval) * (F::ONE - point).invert().unwrap();
            assert_eq!(sim_query_0, query[0][0]);
            assert_eq!(sim_query_1, query[0][1]);
        }
        //	println!("verify corresponding {:?}", now.elapsed());

        //read remaining paths for consistency check with evaluation polynomial
        let remaining_queries = vp.udr_queries.checked_sub(vp.num_verifier_queries);
        let (
            mut queries_usize,
            mut eval_queried_els,
            mut eval_paths,
            mut comm_queried_els,
            mut comm_paths,
        ) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());

        if let Some(a) = remaining_queries {
            let rand_queries = transcript.squeeze_challenges(a);
            queries_usize = get_query_indices(&rand_queries, 1 << (vp.num_vars + vp.log_rate));
            for i in 0..a {
                eval_queried_els.push(transcript.read_field_elements(2).unwrap());
                size = size + 2 * field_size;
            }
            for i in 0..a {
                comm_queried_els.push(transcript.read_field_elements(2).unwrap());
                size = size + 2 * field_size;
            }
            for i in 0..a {
                let merkle_path = transcript
                    .read_commitments(2 * (vp.num_vars + vp.log_rate))
                    .unwrap();
                size = size + 2 * (vp.num_vars + vp.log_rate) * 256;
                let chunked_path = merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();
                eval_paths.push(chunked_path);
            }
            for i in 0..a {
                let merkle_path = transcript
                    .read_commitments(2 * (vp.num_vars + vp.log_rate))
                    .unwrap();
                size = size + 2 * (vp.num_vars + vp.log_rate) * 256;
                let chunked_path = merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();
                comm_paths.push(chunked_path);
            }
        }
        let now = Instant::now();
        for i in 0..eval_paths.len() {
            authenticate_merkle_path::<H, F>(
                &eval_paths[i],
                (eval_queried_els[i][0], eval_queried_els[i][1]),
                queries_usize[i],
            );

            authenticate_merkle_path::<H, F>(
                &comm_paths[i],
                (comm_queried_els[i][0], comm_queried_els[i][1]),
                queries_usize[i],
            );
        }
        //        println!("authenticate time {:?}", now.elapsed());
        //verify corresponding queries are related correctly
        let now = Instant::now();
        for i in 0..eval_queried_els.len() {
            let sim_query_0 = (comm_queried_els[i][0] - eval) * (F::ONE - point).invert().unwrap();
            let sim_query_1 = (comm_queried_els[i][1] - eval) * (F::ONE - point).invert().unwrap();
            assert_eq!(sim_query_0, eval_queried_els[i][0]);
            assert_eq!(sim_query_1, eval_queried_els[i][1]);
        }
        //	println!("corresponding queries {:?}", now.elapsed().as_millis());

        //        println!("Fri effective proof size {:?}", size);

        virtual_open(
            vp.num_vars,
            vp.num_rounds,
            &mut final_oracle,
            &mut fold_challenges,
            &vp.table_w_weights,
        );
      (Ok(()),queries_usize)
}
