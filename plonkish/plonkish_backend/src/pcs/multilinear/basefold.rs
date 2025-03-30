use crate::pcs::Commitment;
use crate::piop::sum_check::{
    classic::{ClassicSumCheck, CoefficientsProver},
    eq_xy_eval, SumCheck as _, VirtualPolynomial,
};
use crate::{
    pcs::{
        multilinear::{additive, validate_input},
        AdditiveCommitment, Evaluation, Point, PolynomialCommitmentScheme,
    },
    poly::{multilinear::MultilinearPolynomial, Polynomial},
    util::{
        arithmetic::{div_ceil, horner, inner_product, steps, BatchInvert, Field, PrimeField},
        code::{Brakedown, BrakedownSpec, LinearCodes},
        expression::{Expression, Query, Rotation},
        hash::{Hash, Output},
        new_fields::{Mersenne127, Mersenne61},
        parallel::{num_threads, parallelize, parallelize_iter},
        transcript::{FieldTranscript, TranscriptRead, TranscriptWrite},
        BigUint, Deserialize, DeserializeOwned, Itertools, Serialize,
    },
    Error,
};
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use core::fmt::Debug;
use core::ptr::addr_of;
use ctr;
use ff::BatchInverter;
use generic_array::GenericArray;
use halo2_curves::bn256::{Bn256, Fr};
use rayon::iter::IntoParallelIterator;
use std::{collections::HashMap, iter, ops::Deref, time::Instant};

use plonky2_util::{reverse_bits, reverse_index_bits_in_place};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha12Rng, ChaCha8Rng,
};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
    ParallelSlice, ParallelSliceMut,
};
use std::{borrow::Cow, marker::PhantomData, mem::size_of, slice};

//The most fundamental building block of basefold is the polynomial. Currently, polynomial's are just expressed as vectors of field elements. Sometimes, vectors are in coefficient form and sometimes they are in evaluation form. Additionally, many functions make assumptions on the order of evaluations of a polynomial. There are two orderings that are used. The first ordering (which we label Type1Polynomial) places "folding pairs" next to each other, for increased parallelizability. eg, the evaluations are as follows:

//Type1Polynomial: vec![P(x1,y1,z1), P(x1,y1,z2), P(x1,y2,z3), P(x1,y2,z4), P(x2,y3,z5), P(x2,y3,z6), P(x2,y4,z7), P(x2,y4,z8)]

//Type2Polynomial has it in the ordering that is described in the Basefold paper, which also lends itself well to fast encoding
//Type2Polynomial:  vec![P(x1,y1,z1), P(x2,y3,z5), P(x1,y2,z3), P(x2,y4,z7), P(x1,y1,z2), P(x2,y3,z6), P(x1,y2,z4), P(x2,y4,z8)]

//Type1Polynomial is a bit-reversal of Type2Polynomial, where the transformation can be done by the function `reverse_index_bits_in_place`, which was taken from `plonky2`.

//Finally, sometimes Type2Polynomial contains coefficients rather than evaluations, in that case it just means that when encoded, it yields evaluations in Type2 order.

#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct Type1Polynomial<F: PrimeField> {
    pub poly: Vec<F>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct Type2Polynomial<F: PrimeField> {
    pub poly: Vec<F>,
}

type SumCheck<F> = ClassicSumCheck<CoefficientsProver<F>>;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldParams<F: PrimeField> {
    log_rate: usize,
    num_verifier_queries: usize,
    pub num_vars: usize,
    pub num_rounds: Option<usize>,
    table_w_weights: Vec<Vec<(F, F)>>,
    table: Vec<Vec<F>>,
    rng: ChaCha8Rng,
    rs_basecode: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldProverParams<F: PrimeField> {
    pub log_rate: usize,
    table_w_weights: Vec<Vec<(F, F)>>,
    pub table: Vec<Vec<F>>,
    num_verifier_queries: usize,
    pub num_vars: usize,
    num_rounds: usize,
    rs_basecode: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasefoldVerifierParams<F: PrimeField> {
    rng: ChaCha8Rng,
    pub num_vars: usize,
    log_rate: usize,
    num_verifier_queries: usize,
    pub num_rounds: usize,
    table_w_weights: Vec<Vec<(F, F)>>,
    rs_basecode: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize", deserialize = "F: DeserializeOwned"))]
pub struct BasefoldCommitment<F: PrimeField, H: Hash> {
    pub codeword: Type1Polynomial<F>,
    codeword_tree: Vec<Vec<Output<H>>>,
    pub bh_evals: Type1Polynomial<F>,
}

impl<F: PrimeField, H: Hash> Default for BasefoldCommitment<F, H> {
    fn default() -> Self {
        Self {
            codeword: Type1Polynomial { poly: Vec::new() },
            codeword_tree: vec![vec![Output::<H>::default()]],
            bh_evals: Type1Polynomial { poly: Vec::new() },
        }
    }
}

impl<F: PrimeField, H: Hash> BasefoldCommitment<F, H> {
    fn from_root(root: Output<H>) -> Self {
        Self {
            codeword: Type1Polynomial { poly: Vec::new() },
            codeword_tree: vec![vec![root]],
            bh_evals: Type1Polynomial { poly: Vec::new() },
        }
    }
}
impl<F: PrimeField, H: Hash> PartialEq for BasefoldCommitment<F, H> {
    fn eq(&self, other: &Self) -> bool {
        self.codeword.poly.eq(&other.codeword.poly)
            && self.codeword_tree.eq(&other.codeword_tree)
            && self.bh_evals.poly.eq(&other.bh_evals.poly)
    }
}

impl<F: PrimeField, H: Hash> Eq for BasefoldCommitment<F, H> {}

pub trait BasefoldExtParams: Debug {
    fn get_reps() -> usize;

    fn get_rate() -> usize;

    fn get_basecode_rounds() -> usize;

    fn get_rs_basecode() -> bool;
}

#[derive(Debug)]
pub struct Basefold<F: PrimeField, H: Hash, V: BasefoldExtParams>(PhantomData<(F, H, V)>);

impl<F: PrimeField, H: Hash, V: BasefoldExtParams> Clone for Basefold<F, H, V> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<F: PrimeField, H: Hash> AsRef<[Output<H>]> for BasefoldCommitment<F, H> {
    fn as_ref(&self) -> &[Output<H>] {
        let root = &self.codeword_tree[self.codeword_tree.len() - 1][0];
        slice::from_ref(root)
    }
}

impl<F: PrimeField, H: Hash> AsRef<Output<H>> for BasefoldCommitment<F, H> {
    fn as_ref(&self) -> &Output<H> {
        let root = &self.codeword_tree[self.codeword_tree.len() - 1][0];
        &root
    }
}
impl<F: PrimeField, H: Hash> AdditiveCommitment<F> for BasefoldCommitment<F, H> {
    fn sum_with_scalar<'a>(
        scalars: impl IntoIterator<Item = &'a F> + 'a,
        bases: impl IntoIterator<Item = &'a Self> + 'a,
    ) -> Self {
        let bases = bases.into_iter().collect_vec();

        let scalars = scalars.into_iter().collect_vec();
        let bases = bases.into_iter().collect_vec();
        let k = bases[0].bh_evals.poly.len();

        let mut new_codeword = vec![F::ZERO; bases[0].codeword.poly.len()];
        new_codeword
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, mut c)| {
                for j in 0..bases.len() {
                    *c += *scalars[j] * bases[j].codeword.poly[i];
                }
            });

        let mut new_bh_eval = vec![F::ZERO; k];
        new_bh_eval
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, mut c)| {
                for j in 0..bases.len() {
                    *c += *scalars[j] * bases[j].bh_evals.poly[i];
                }
            });

        let cw = Type1Polynomial { poly: new_codeword };
        let tree = merkelize::<F, H>(&cw);

        Self {
            codeword: cw,
            bh_evals: Type1Polynomial { poly: Vec::new() },
            codeword_tree: tree,
        }
    }
}
impl<F, H, V> PolynomialCommitmentScheme<F> for Basefold<F, H, V>
where
    F: PrimeField + Serialize + DeserializeOwned,
    H: Hash,
    V: BasefoldExtParams,
{
    type Param = BasefoldParams<F>;
    type ProverParam = BasefoldProverParams<F>;
    type VerifierParam = BasefoldVerifierParams<F>;
    type Polynomial = MultilinearPolynomial<F>;
    type Commitment = BasefoldCommitment<F, H>;
    type CommitmentChunk = Output<H>;

    fn setup(poly_size: usize, _: usize, rng: impl RngCore) -> Result<Self::Param, Error> {
        let log_rate = V::get_rate();
        let mut test_rng = ChaCha8Rng::from_entropy();
        let (table_w_weights, table) = get_table_aes(poly_size, log_rate, &mut test_rng);
        let mut rs_basecode = false;
        if V::get_rs_basecode() == true && V::get_basecode_rounds() > 0 {
            rs_basecode = true;
        }
        Ok(BasefoldParams {
            log_rate: log_rate,
            num_verifier_queries: V::get_reps(),
            num_vars: log2_strict(poly_size),
            num_rounds: Some(log2_strict(poly_size) - V::get_basecode_rounds()),
            table_w_weights: table_w_weights,
            table: table,
            rng: test_rng.clone(),
            rs_basecode: rs_basecode,
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
            BasefoldProverParams {
                log_rate: param.log_rate,
                table_w_weights: param.table_w_weights.clone(),
                table: param.table.clone(),
                num_verifier_queries: param.num_verifier_queries,
                num_vars: param.num_vars,
                num_rounds: rounds,
                rs_basecode: param.rs_basecode,
            },
            BasefoldVerifierParams {
                rng: param.rng.clone(),
                num_vars: param.num_vars,
                log_rate: param.log_rate,
                num_verifier_queries: param.num_verifier_queries,
                num_rounds: rounds,
                table_w_weights: param.table_w_weights.clone(),
                rs_basecode: param.rs_basecode,
            },
        ))
    }

    fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Result<Self::Commitment, Error> {
        let p = Type2Polynomial {
            poly: poly.evals().to_vec(),
        };
        let (coeffs, mut bh_evals) = interpolate_over_boolean_hypercube_with_copy(&p);

        let mut commitment = Type1Polynomial::default();
        if (pp.rs_basecode) {
            let mut basecode = encode_rs_basecode(
                &coeffs,
                1 << pp.log_rate,
                1 << (pp.num_vars - pp.num_rounds),
            );
            assert_eq!(basecode.poly.len() > 0, true);

            commitment = evaluate_over_foldable_domain_2(
                pp.num_vars - pp.num_rounds + pp.log_rate,
                pp.log_rate,
                basecode,
                &pp.table,
            );
        } else {
            commitment = evaluate_over_foldable_domain(pp.log_rate, coeffs, &pp.table);
        }

        let tree = merkelize::<F, H>(&commitment);

        Ok(Self::Commitment {
            codeword: commitment,
            codeword_tree: tree,
            bh_evals: bh_evals,
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
        let polys_vec: Vec<&Self::Polynomial> = polys.into_iter().map(|poly| poly).collect();
        polys_vec
            .par_iter()
            .map(|poly| Self::commit(pp, poly))
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
        let (trees, sum_check_oracles, mut oracles, mut bh_evals, mut eq, eval) = commit_phase(
            &point,
            &comm,
            transcript,
            pp.num_vars,
            pp.num_rounds,
            &pp.table_w_weights,
        );

        let (queried_els, queries_usize_) =
            query_phase(transcript, &comm, &oracles, pp.num_verifier_queries);

        // a proof consists of roots, merkle paths, query paths, sum check oracles, eval, and final oracle

        transcript.write_field_element(&eval); //write eval

        if pp.num_rounds < pp.num_vars {
            transcript.write_field_elements(&bh_evals.poly); //write bh_evals
            transcript.write_field_elements(&eq.poly); //write eq
        }

        //write final oracle
        let mut final_oracle = oracles.pop().unwrap();
        transcript.write_field_elements(&final_oracle.poly);

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
                    write_merkle_path::<H, F>(&comm.codeword_tree, *q, transcript);
                } else {
                    write_merkle_path::<H, F>(&trees[i - 1], *q, transcript);
                }
            })
        });

        Ok(())
    }

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        use std::env;

        let polys = polys.into_iter().collect_vec();
        let comms = comms.into_iter().collect_vec();

        validate_input("batch open", pp.num_vars, polys.clone(), points)?;
        for comm in &comms {
            transcript.write_commitment(&comm.as_ref());
        }
        let ell = evals.len().next_power_of_two().ilog2() as usize;
        let t = transcript.squeeze_challenges(ell);

        let eq_xt = MultilinearPolynomial::eq_xy(&t);
        let merged_polys = evals.iter().zip(eq_xt.evals().iter()).fold(
            vec![(F::ONE, Cow::<MultilinearPolynomial<_>>::default()); points.len()],
            |mut merged_polys, (eval, eq_xt_i)| {
                if merged_polys[eval.point()].1.is_zero() {
                    merged_polys[eval.point()] = (*eq_xt_i, Cow::Borrowed(polys[eval.poly()]));
                } else {
                    let coeff = merged_polys[eval.point()].0;
                    if coeff != F::ONE {
                        merged_polys[eval.point()].0 = F::ONE;
                        *merged_polys[eval.point()].1.to_mut() *= &coeff;
                    }
                    *merged_polys[eval.point()].1.to_mut() += (eq_xt_i, polys[eval.poly()]);
                }
                merged_polys
            },
        );

        let unique_merged_polys = merged_polys
            .iter()
            .unique_by(|(_, poly)| addr_of!(*poly.deref()))
            .collect_vec();
        let unique_merged_poly_indices = unique_merged_polys
            .iter()
            .enumerate()
            .map(|(idx, (_, poly))| (addr_of!(*poly.deref()), idx))
            .collect::<HashMap<_, _>>();
        let expression = merged_polys
            .iter()
            .enumerate()
            .map(|(idx, (scalar, poly))| {
                let poly = unique_merged_poly_indices[&addr_of!(*poly.deref())];
                Expression::<F>::eq_xy(idx)
                    * Expression::Polynomial(Query::new(poly, Rotation::cur()))
                    * scalar
            })
            .sum();
        let virtual_poly = VirtualPolynomial::new(
            &expression,
            unique_merged_polys.iter().map(|(_, poly)| poly.deref()),
            &[],
            points,
        );
        let tilde_gs_sum =
            inner_product(evals.iter().map(Evaluation::value), &eq_xt[..evals.len()]);
        let now = Instant::now();
        let (challenges, _) =
            SumCheck::prove(&(), pp.num_vars, virtual_poly, tilde_gs_sum, transcript)?;

        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&challenges, point))
            .collect_vec();
        let g_prime = merged_polys
            .into_iter()
            .zip(eq_xy_evals.iter())
            .map(|((scalar, poly), eq_xy_eval)| (scalar * eq_xy_eval, poly.into_owned()))
            .sum::<MultilinearPolynomial<_>>();

        let (mut comm, eval) = if cfg!(feature = "sanity-check") {
            let scalars = evals
                .iter()
                .zip(eq_xt.evals())
                .map(|(eval, eq_xt_i)| eq_xy_evals[eval.point()] * eq_xt_i)
                .collect_vec();
            let bases = evals.iter().map(|eval| comms[eval.poly()]);
            let now = Instant::now();
            let comm = Self::Commitment::sum_with_scalar(&scalars, bases);

            (comm, g_prime.evaluate(&challenges))
        } else {
            (Self::Commitment::default(), F::ZERO)
        };
        let mut bh_evals = g_prime.evals().to_vec();

        //convert to type 1
        reverse_index_bits_in_place(&mut bh_evals);

        comm.bh_evals = Type1Polynomial { poly: bh_evals };
        let point = challenges;

        let (trees, sum_check_oracles, mut oracles, bh_evals, eq, eval) = commit_phase(
            &point,
            &comm,
            transcript,
            pp.num_vars,
            pp.num_rounds,
            &pp.table_w_weights,
        );

        if pp.num_rounds < pp.num_vars {
            transcript.write_field_elements(&bh_evals.poly);
            transcript.write_field_elements(&eq.poly);
        }

        let (queried_els, queries_usize) =
            query_phase(transcript, &comm, &oracles, pp.num_verifier_queries);

        let mut individual_queries: Vec<Vec<(F, F)>> = Vec::with_capacity(queries_usize.len());

        let mut individual_paths: Vec<Vec<Vec<(Output<H>, Output<H>)>>> =
            Vec::with_capacity(queries_usize.len());
        for query in &queries_usize {
            let mut comm_queries = Vec::with_capacity(evals.len());
            let mut comm_paths = Vec::with_capacity(evals.len());
            for eval in evals {
                let c = comms[eval.poly()];
                let res = query_codeword::<F, H>(query, &c.codeword.poly, &c.codeword_tree);
                comm_queries.push(res.0);
                comm_paths.push(res.1);
            }

            individual_queries.push(comm_queries);
            individual_paths.push(comm_paths);
        }

        let merkle_paths: Vec<Vec<Vec<(Output<H>, Output<H>)>>> = queried_els
            .iter()
            .map(|query| {
                let indices = &query.1;
                indices
                    .into_iter()
                    .enumerate()
                    .map(|(i, q)| {
                        if (i == 0) {
                            return get_merkle_path::<H, F>(&comm.codeword_tree, *q, false);
                        } else {
                            return get_merkle_path::<H, F>(&trees[i - 1], *q, false);
                        }
                    })
                    .collect()
            })
            .collect();

        // a proof consists of roots, merkle paths, query paths, sum check oracles, eval, and final oracle
        //write individual commitment queries for batching
        //queries for batch
        individual_queries.iter().flatten().for_each(|(f1, f2)| {
            transcript.write_field_element(f1).unwrap();
            transcript.write_field_element(f2).unwrap();
        });
        //paths for batch
        individual_paths
            .iter()
            .flatten()
            .flatten()
            .for_each(|(h1, h2)| {
                transcript.write_commitment(h1);
                transcript.write_commitment(h2);
            });

        //write sum check oracles

        //write eval
        transcript.write_field_element(&eval);
        //write final oracle
        transcript.write_field_elements(oracles.pop().unwrap().poly.iter().collect_vec());
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
        merkle_paths
            .iter()
            .flatten()
            .flatten()
            .for_each(|(h1, h2)| {
                transcript.write_commitment(h1);
                transcript.write_commitment(h2);
            });

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
            .map(|r| BasefoldCommitment::from_root(r.clone()))
            .collect_vec())
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        let field_size = 255;
        let n = (1 << (vp.num_vars + vp.log_rate));
        //read first $(num_var - 1) commitments

        let mut fold_challenges: Vec<F> = Vec::with_capacity(vp.num_vars);
        let mut size = 0;
        let mut roots = Vec::new();
        let mut sum_check_oracles = Vec::new();
        for i in 0..vp.num_rounds {
            roots.push(transcript.read_commitment().unwrap());
            sum_check_oracles.push(transcript.read_field_elements(3).unwrap());
            fold_challenges.push(transcript.squeeze_challenge());
        }
        sum_check_oracles.push(transcript.read_field_elements(3).unwrap());

        let mut query_challenges = transcript.squeeze_challenges(vp.num_verifier_queries);

        size = size + field_size * (3 * (vp.num_rounds + 1));
        //read eval

        let eval = &transcript.read_field_element().unwrap(); //do not need eval in proof

        let mut bh_evals = Vec::new();
        let mut eq = Vec::new();
        if vp.num_rounds < vp.num_vars {
            bh_evals = transcript
                .read_field_elements(1 << (vp.num_vars - vp.num_rounds))
                .unwrap();
            eq = transcript
                .read_field_elements(1 << (vp.num_vars - vp.num_rounds))
                .unwrap();
            size = size + field_size * (bh_evals.len() + eq.len());
        }

        //read final oracle
        let mut final_oracle = transcript
            .read_field_elements(1 << (vp.num_vars - vp.num_rounds + vp.log_rate))
            .unwrap();

        size = size + field_size * final_oracle.len();
        //read query paths
        let num_queries = vp.num_verifier_queries * 2 * (vp.num_rounds + 1);

        let all_qs = transcript.read_field_elements(num_queries).unwrap();

        size = size + (num_queries - 2) * field_size;
        //        println!("size for all iop queries {:?}", size);

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

        verifier_query_phase::<F, H>(
            &query_challenges,
            &query_merkle_paths,
            &sum_check_oracles,
            &fold_challenges,
            &queries,
            vp.num_rounds,
            vp.num_vars,
            vp.log_rate,
            &roots,
            vp.rng.clone(),
            &eval,
        );
        let mut next_oracle = Type1Polynomial { poly: final_oracle };
        let mut bh_evals = Type1Polynomial { poly: bh_evals };
        let mut eq = Type1Polynomial { poly: eq };
        if (!vp.rs_basecode) {
            virtual_open(
                vp.num_vars,
                vp.num_rounds,
                &mut eq,
                &mut bh_evals,
                &mut next_oracle,
                point,
                &mut fold_challenges,
                &vp.table_w_weights,
                &mut sum_check_oracles,
            );
        } else {
            one_level_reverse_interp_hc(&mut bh_evals);
            reverse_index_bits_in_place(&mut bh_evals.poly); //convert to type2
            let (mut new_coeffs, _) =
                interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
                    poly: bh_evals.poly,
                });

            let rs = encode_rs_basecode(
                &new_coeffs,
                1 << vp.log_rate,
                1 << (vp.num_vars - vp.num_rounds),
            );

            reverse_index_bits_in_place(&mut next_oracle.poly); //convert to type2
            assert_eq!(
                rs,
                Type2Polynomial {
                    poly: next_oracle.poly
                }
            );
        }
        Ok(())
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        use std::env;

        let comms = comms.into_iter().collect_vec();
        validate_input("batch verify", vp.num_vars, [], points)?;
        transcript.read_commitments(comms.len());

        let ell = evals.len().next_power_of_two().ilog2() as usize;

        let t = transcript.squeeze_challenges(ell);

        let eq_xt = MultilinearPolynomial::eq_xy(&t);
        let tilde_gs_sum =
            inner_product(evals.iter().map(Evaluation::value), &eq_xt[..evals.len()]);

        let (g_prime_eval, verify_point) =
            SumCheck::verify(&(), vp.num_vars, 2, tilde_gs_sum, transcript)?;

        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&verify_point, point))
            .collect_vec();

        //start of verify
        let n = (1 << (vp.num_vars + vp.log_rate));
        //read first $(num_var - 1) commitments
        let mut roots: Vec<Output<H>> = Vec::with_capacity(vp.num_rounds + 1);
        let mut fold_challenges: Vec<F> = Vec::with_capacity(vp.num_rounds);
        let mut sum_check_oracles = Vec::new();
        for i in 0..vp.num_rounds {
            roots.push(transcript.read_commitment().unwrap());
            sum_check_oracles.push(transcript.read_field_elements(3).unwrap());
            fold_challenges.push(transcript.squeeze_challenge());
        }
        sum_check_oracles.push(transcript.read_field_elements(3).unwrap());
        let mut bh_evals = Vec::new();
        let mut eq = Vec::new();
        if vp.num_rounds < vp.num_vars {
            bh_evals = transcript
                .read_field_elements(1 << (vp.num_vars - vp.num_rounds))
                .unwrap();
            eq = transcript
                .read_field_elements(1 << (vp.num_vars - vp.num_rounds))
                .unwrap();
        }

        let mut query_challenges = transcript.squeeze_challenges(vp.num_verifier_queries);

        let mut ind_queries = Vec::with_capacity(vp.num_verifier_queries);
        let mut count = 0;
        for i in 0..vp.num_verifier_queries {
            let mut comms_queries = Vec::with_capacity(evals.len());
            for j in 0..evals.len() {
                let queries = transcript.read_field_elements(2).unwrap();

                comms_queries.push(queries);
            }

            ind_queries.push(comms_queries);
        }

        //read merkle paths
        let mut batch_paths = Vec::with_capacity(vp.num_verifier_queries);
        let mut count = 0;
        for i in 0..vp.num_verifier_queries {
            let mut comms_merkle_paths = Vec::with_capacity(evals.len());
            for j in 0..evals.len() {
                let merkle_path = transcript
                    .read_commitments(2 * (vp.num_vars + vp.log_rate))
                    .unwrap();
                let chunked_path = merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();

                comms_merkle_paths.push(chunked_path);
            }

            batch_paths.push(comms_merkle_paths);
        }

        let mut count = 0;

        //read eval
        let eval = transcript.read_field_element().unwrap();

        //read final oracle
        let mut final_oracle = transcript
            .read_field_elements(1 << (vp.num_vars - vp.num_rounds + vp.log_rate))
            .unwrap();

        //read query paths
        let num_queries = vp.num_verifier_queries * 2 * (vp.num_rounds + 1);

        let all_qs = transcript.read_field_elements(num_queries).unwrap();

        let i_qs = all_qs.chunks((vp.num_rounds + 1) * 2).collect_vec();

        assert_eq!(i_qs.len(), vp.num_verifier_queries);

        let mut queries = i_qs.iter().map(|q| q.chunks(2).collect_vec()).collect_vec();

        assert_eq!(queries[0][0].len(), 2);

        let scalars = evals
            .iter()
            .zip(eq_xt.evals())
            .map(|(eval, eq_xt_i)| eq_xy_evals[eval.point()] * eq_xt_i)
            .collect_vec();

        for (i, query) in queries.iter().enumerate() {
            let mut lc0 = F::ZERO;
            let mut lc1 = F::ZERO;
            for j in 0..scalars.len() {
                lc0 += scalars[j] * ind_queries[i][j][0];
                lc1 += scalars[j] * ind_queries[i][j][1];
            }
            assert_eq!(query[0][0], lc0);
            assert_eq!(query[0][1], lc1);
        }

        //start regular verify on the proof in transcript

        let mut query_merkle_paths: Vec<Vec<Vec<Vec<Output<H>>>>> =
            Vec::with_capacity(vp.num_verifier_queries);
        for i in 0..vp.num_verifier_queries {
            let mut merkle_paths: Vec<Vec<Vec<Output<H>>>> = Vec::with_capacity(vp.num_rounds + 1);
            for round in 0..(vp.num_rounds + 1) {
                let merkle_path: Vec<Output<H>> = transcript
                    .read_commitments(2 * (vp.num_vars - round + vp.log_rate - 1)) //-1 because we already read roots
                    .unwrap();
                let chunked_path: Vec<Vec<Output<H>>> =
                    merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();

                merkle_paths.push(chunked_path);
            }
            query_merkle_paths.push(merkle_paths);
        }

        let queries_usize = verifier_query_phase::<F, H>(
            &query_challenges,
            &query_merkle_paths,
            &sum_check_oracles,
            &fold_challenges,
            &queries,
            vp.num_rounds,
            vp.num_vars,
            vp.log_rate,
            &roots,
            vp.rng.clone(),
            &eval,
        );

        for vq in 0..vp.num_verifier_queries {
            for cq in 0..ind_queries[vq].len() {
                let tree = &comms[evals[cq].poly].codeword_tree;
                assert_eq!(
                    tree[tree.len() - 1][0],
                    batch_paths[vq][cq].pop().unwrap().pop().unwrap()
                );

                authenticate_merkle_path::<H, F>(
                    &batch_paths[vq][cq],
                    (ind_queries[vq][cq][0], ind_queries[vq][cq][1]),
                    queries_usize[vq],
                );

                count += 1;
            }
        }
        let mut next_oracle = Type1Polynomial { poly: final_oracle };
        let mut bh_evals = Type1Polynomial { poly: bh_evals };
        let mut eq = Type1Polynomial { poly: eq };
        if (!vp.rs_basecode) {
            virtual_open(
                vp.num_vars,
                vp.num_rounds,
                &mut eq,
                &mut bh_evals,
                &mut next_oracle,
                &verify_point,
                &mut fold_challenges,
                &vp.table_w_weights,
                &mut sum_check_oracles,
            );
        } else {
            one_level_reverse_interp_hc(&mut bh_evals);
            reverse_index_bits_in_place(&mut bh_evals.poly); //convert to type2
            let (mut new_coeffs, _) =
                interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
                    poly: bh_evals.poly,
                });

            let rs = encode_rs_basecode(
                &new_coeffs,
                1 << vp.log_rate,
                1 << (vp.num_vars - vp.num_rounds),
            );
            reverse_index_bits_in_place(&mut next_oracle.poly); //convert to type2
            assert_eq!(
                rs,
                Type2Polynomial {
                    poly: next_oracle.poly
                }
            );
        }
        Ok(())
    }
}

#[test]
fn time_rs_code() {
    use blake2::Blake2s256;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let mut poly = MultilinearPolynomial::rand(20, OsRng);
    let mut t_rng = ChaCha8Rng::from_entropy();

    let rate = 2;
    let now = Instant::now();
    let evals = encode_rs_basecode::<Mersenne61>(
        &Type2Polynomial {
            poly: poly.evals().to_vec(),
        },
        2,
        64,
    );
}
fn encode_rs_basecode<F: PrimeField>(
    poly: &Type2Polynomial<F>,
    rate: usize,
    message_size: usize,
) -> Type2Polynomial<F> {
    let domain: Vec<F> = steps(F::ONE).take(message_size * rate).collect();
    let res = poly
        .poly
        .par_chunks_exact(message_size)
        .map(|chunk| {
            let mut target = vec![F::ZERO; message_size * rate];
            target
                .iter_mut()
                .enumerate()
                .for_each(|(i, target)| *target = horner(&chunk[..], &domain[i]));
            target
        })
        .collect::<Vec<Vec<F>>>();

    let result = res.iter().flatten().map(|x| *x).collect::<Vec<F>>();
    Type2Polynomial { poly: result }
}

fn encode_repetition_basecode<F: PrimeField>(
    poly: &Type2Polynomial<F>,
    rate: usize,
) -> Vec<Type2Polynomial<F>> {
    let mut base_codewords = Vec::new();
    for c in &poly.poly {
        let mut rep_code = Vec::new();
        for i in 0..rate {
            rep_code.push(*c);
        }
        base_codewords.push(Type2Polynomial { poly: rep_code });
    }
    return base_codewords;
}
//this function assumes all codewords in base_codeword has equivalent length
pub fn evaluate_over_foldable_domain_generic_basecode<F: PrimeField>(
    base_message_length: usize,
    num_coeffs: usize,
    log_rate: usize,
    mut base_codewords: Type2Polynomial<F>,
    table: &Vec<Vec<F>>,
) -> Type1Polynomial<F> {
    let k = num_coeffs;
    let logk = log2_strict(k);
    let cl = 1 << (logk + log_rate);

    let rate = 1 << log_rate;
    let base_log_k = log2_strict(base_message_length);

    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let mut chunk_size = 1 << base_log_k; //block length of the base code
    for i in base_log_k..logk {
        let level = &table[i + log_rate];
        chunk_size = chunk_size << 1;
        assert_eq!(level.len(), chunk_size >> 1);
        <Vec<F> as AsMut<[F]>>::as_mut(&mut base_codewords.poly)
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
    reverse_index_bits_in_place(&mut base_codewords.poly);
    Type1Polynomial {
        poly: base_codewords.poly,
    }
}

pub fn evaluate_over_foldable_domain<F: PrimeField>(
    log_rate: usize,
    mut coeffs: Type2Polynomial<F>,
    table: &Vec<Vec<F>>,
) -> Type1Polynomial<F> {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let k = coeffs.poly.len();
    let logk = log2_strict(k);
    let cl = 1 << (logk + log_rate);
    let rate = 1 << log_rate;

    let mut coeffs_with_rep = vec![F::ZERO; cl];

    //base code - in this case is the repetition code

    for i in 0..k {
        for j in 0..rate {
            coeffs_with_rep[i * rate + j] = coeffs.poly[i];
        }
    }

    let mut chunk_size = rate; //block length of the base code
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
    reverse_index_bits_in_place(&mut coeffs_with_rep);
    Type1Polynomial {
        poly: coeffs_with_rep,
    }
}

pub fn evaluate_over_foldable_domain_2<F: PrimeField>(
    log_chunk_size: usize,
    log_rate: usize,
    mut coeffs: Type2Polynomial<F>,
    table: &Vec<Vec<F>>,
) -> Type1Polynomial<F> {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let mut chunk_size = 1 << log_chunk_size;
    let levels = log2_strict(coeffs.poly.len()) - log_chunk_size;

    for i in 0..levels {
        let level = &table[i + log_chunk_size];
        chunk_size = chunk_size << 1;
        assert_eq!(level.len(), chunk_size >> 1);
        <Vec<F> as AsMut<[F]>>::as_mut(&mut coeffs.poly)
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
    reverse_index_bits_in_place(&mut coeffs.poly);
    Type1Polynomial { poly: coeffs.poly }
}

pub fn interpolate_over_boolean_hypercube_with_copy<F: PrimeField>(
    evals: &Type2Polynomial<F>,
) -> (Type2Polynomial<F>, Type1Polynomial<F>) {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let n = log2_strict(evals.poly.len());
    let mut coeffs = vec![F::ZERO; evals.poly.len()];
    let mut new_evals = vec![F::ZERO; evals.poly.len()];

    let mut j = 0;
    while (j < coeffs.len()) {
        new_evals[j] = evals.poly[j];
        new_evals[j + 1] = evals.poly[j + 1];

        coeffs[j + 1] = evals.poly[j + 1] - evals.poly[j];
        coeffs[j] = evals.poly[j];
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
    reverse_index_bits_in_place(&mut new_evals);
    (
        Type2Polynomial { poly: coeffs },
        Type1Polynomial { poly: new_evals },
    )
}

//helper function
fn rand_vec<F: PrimeField>(size: usize, mut rng: &mut ChaCha8Rng) -> Vec<F> {
    (0..size).map(|_| F::random(&mut rng)).collect()
}
fn rand_chacha<F: PrimeField>(mut rng: &mut ChaCha8Rng) -> F {
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

pub fn merkelize<F: PrimeField, H: Hash>(values: &Type1Polynomial<F>) -> Vec<Vec<Output<H>>> {
    let log_v = log2_strict(values.poly.len());
    let mut tree = Vec::with_capacity(log_v);
    let mut hashes = vec![Output::<H>::default(); (values.poly.len() >> 1)];
    let method1 = Instant::now();
    hashes.par_iter_mut().enumerate().for_each(|(i, mut hash)| {
        let mut hasher = H::new();
        hasher.update_field_element(&values.poly[i + i]);
        hasher.update_field_element(&values.poly[i + i + 1]);
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

pub fn build_eq_x_r_vec<F: PrimeField>(r: &[F]) -> Option<Vec<F>> {
    // we build eq(x,r) from its evaluations
    // we want to evaluate eq(x,r) over x \in {0, 1}^num_vars
    // for example, with num_vars = 4, x is a binary vector of 4, then
    //  0 0 0 0 -> (1-r0)   * (1-r1)    * (1-r2)    * (1-r3)
    //  1 0 0 0 -> r0       * (1-r1)    * (1-r2)    * (1-r3)
    //  0 1 0 0 -> (1-r0)   * r1        * (1-r2)    * (1-r3)
    //  1 1 0 0 -> r0       * r1        * (1-r2)    * (1-r3)
    //  ....
    //  1 1 1 1 -> r0       * r1        * r2        * r3
    // we will need 2^num_var evaluations

    let mut eval = Vec::new();
    build_eq_x_r_helper(r, &mut eval);

    Some(eval)
}

/// A helper function to build eq(x, r) recursively.
/// This function takes `r.len()` steps, and for each step it requires a maximum
/// `r.len()-1` multiplications.
fn build_eq_x_r_helper<F: PrimeField>(r: &[F], buf: &mut Vec<F>) {
    assert!(!r.is_empty(), "r length is 0");

    if r.len() == 1 {
        // initializing the buffer with [1-r_0, r_0]
        buf.push(F::ONE - r[0]);
        buf.push(r[0]);
    } else {
        build_eq_x_r_helper(&r[1..], buf);

        // suppose at the previous step we received [b_1, ..., b_k]
        // for the current step we will need
        // if x_0 = 0:   (1-r0) * [b_1, ..., b_k]
        // if x_0 = 1:   r0 * [b_1, ..., b_k]
        // let mut res = vec![];
        // for &b_i in buf.iter() {
        //     let tmp = r[0] * b_i;
        //     res.push(b_i - tmp);
        //     res.push(tmp);
        // }
        // *buf = res;

        let mut res = vec![F::ZERO; buf.len() << 1];
        res.par_iter_mut().enumerate().for_each(|(i, val)| {
            let bi = buf[i >> 1];
            let tmp = r[0] * bi;
            if i & 1 == 0 {
                *val = bi - tmp;
            } else {
                *val = tmp;
            }
        });
        *buf = res;
    }
}

pub fn sum_check_first_round<F: PrimeField>(
    mut eq: &mut Type1Polynomial<F>,
    mut bh_values: &mut Type1Polynomial<F>,
) -> Vec<F> {
    one_level_interp_hc(&mut eq);
    one_level_interp_hc(&mut bh_values);
    parallel_pi(bh_values, eq)
}

pub fn one_level_interp_hc<F: PrimeField>(mut evals: &mut Type1Polynomial<F>) {
    if (evals.poly.len() == 1) {
        return;
    }
    evals.poly.par_chunks_mut(2).for_each(|chunk| {
        chunk[1] = chunk[1] - chunk[0];
    });
}

pub fn one_level_reverse_interp_hc<F: PrimeField>(mut evals: &mut Type1Polynomial<F>) {
    if (evals.poly.len() == 1) {
        return;
    }
    evals.poly.par_chunks_mut(2).for_each(|chunk| {
        chunk[1] = chunk[1] + chunk[0];
    });
}

pub fn one_level_eval_hc<F: PrimeField>(mut evals: &mut Type1Polynomial<F>, challenge: F) {
    evals.poly.par_chunks_mut(2).for_each(|chunk| {
        chunk[1] = chunk[0] + challenge * chunk[1];
    });
    let mut index = 0;

    evals.poly.retain(|v| {
        index += 1;
        (index - 1) % 2 == 1
    });
}

pub fn p_i<F: PrimeField>(evals: &Type1Polynomial<F>, eq: &Type1Polynomial<F>) -> Vec<F> {
    if (evals.poly.len() == 1) {
        return vec![evals.poly[0], evals.poly[0], evals.poly[0]];
    }
    //evals coeffs
    let mut coeffs = vec![F::ZERO, F::ZERO, F::ZERO];
    let mut i = 0;
    while (i < evals.poly.len()) {
        coeffs[0] += evals.poly[i] * eq.poly[i];
        coeffs[1] += evals.poly[i + 1] * eq.poly[i] + evals.poly[i] * eq.poly[i + 1];
        coeffs[2] += evals.poly[i + 1] * eq.poly[i + 1];
        i += 2;
    }

    coeffs
}

fn parallel_pi<F: PrimeField>(evals: &Type1Polynomial<F>, eq: &Type1Polynomial<F>) -> Vec<F> {
    if (evals.poly.len() == 1) {
        return vec![evals.poly[0], evals.poly[0], evals.poly[0]];
    }
    let mut coeffs = vec![F::ZERO, F::ZERO, F::ZERO];

    let mut firsts = vec![F::ZERO; evals.poly.len()];
    firsts.par_iter_mut().enumerate().for_each(|(i, mut f)| {
        if (i % 2 == 0) {
            *f = evals.poly[i] * eq.poly[i];
        }
    });

    let mut seconds = vec![F::ZERO; evals.poly.len()];
    seconds.par_iter_mut().enumerate().for_each(|(i, mut f)| {
        if (i % 2 == 0) {
            *f = evals.poly[i + 1] * eq.poly[i] + evals.poly[i] * eq.poly[i + 1];
        }
    });

    let mut thirds = vec![F::ZERO; evals.poly.len()];
    thirds.par_iter_mut().enumerate().for_each(|(i, mut f)| {
        if (i % 2 == 0) {
            *f = evals.poly[i + 1] * eq.poly[i + 1];
        }
    });

    coeffs[0] = firsts.par_iter().sum();
    coeffs[1] = seconds.par_iter().sum();
    coeffs[2] = thirds.par_iter().sum();

    coeffs
}
/*
fn nd_array_pi<F: PrimeField>(evals: &Vec<F>, eq: &Vec<F>) -> Vec<F> {
    if (evals.len() == 1) {
        return vec![evals[0], evals[0], evals[0]];
    }
    let evals_array = Array1::from(evals);
    let eq_array = Array1::from(eq);

    let evals_evens = Array1::from(evals.par_iter().enumerate().filter(|(i,x)| i%2 == 0).collect::<Vec<F>>());

    let evals_odd = Array1::from(evals.par_iter().enumerate().filter(|(i,x)| i%2 != 0).collect::<Vec<F>>());

    let eq_evens = Array1::from(eq.par_iter().enumerate().filter(|(i,x)| i%2 == 0).collect::<Vec<F>>());

    let eq_odd = Array1::from(eq.par_iter().enumerate().filter(|(i,x)| i%2 != 0).collect::<Vec<F>>());
    let dot1 = evals_array.dot(eq_array);
    let dot2 = evals_odd.dot(eq_even);
    let dot3 = evals_even.dot(eq_odd);
    let dot4 = evals_odd.dot(eq_odd);
    return vec![dot1,dot2 + dot3, dot4];
}
*/
#[test]
fn test_sumcheck() {
    let i = 25;
    let mut rng = ChaCha8Rng::from_entropy();
    let evals = Type1Polynomial {
        poly: rand_vec::<Mersenne61>(1 << i, &mut rng),
    };
    let eq = Type1Polynomial {
        poly: rand_vec::<Mersenne61>(1 << i, &mut rng),
    };
    let now = Instant::now();
    let coeffs1 = p_i(&evals, &eq);
    //    println!("original {:?}", now.elapsed());

    let now = Instant::now();
    let coeffs2 = parallel_pi(&evals, &eq);
    //    println!("new {:?}", now.elapsed());
    assert_eq!(coeffs1, coeffs2);
}

fn sum_check<F: PrimeField>(
    poly: Type1Polynomial<F>,
    point: Vec<F>,
    num_vars: usize,
    num_rounds: usize,
    eq: Vec<F>,
) -> Vec<Vec<F>> {
    let mut eval = F::ZERO;
    let mut bh_evals = Type1Polynomial {
        poly: Vec::with_capacity(1 << num_vars),
    };
    for i in 0..eq.len() {
        eval = eval + poly.poly[i] * eq[i];
        bh_evals.poly.push(poly.poly[i]);
    }

    let mut eq = Type1Polynomial { poly: eq };
    let mut sum_check_oracles_vec = Vec::with_capacity(num_rounds + 1);

    let mut sum_check_oracle = sum_check_first_round::<F>(&mut eq, &mut bh_evals);
    sum_check_oracles_vec.push(sum_check_oracle.clone());
    for i in 0..(num_rounds) {
        let mut rng = ChaCha8Rng::from_entropy();
        let challenge: F = rand_chacha(&mut rng);

        sum_check_oracle = sum_check_challenge_round(&mut eq, &mut bh_evals, challenge);

        sum_check_oracles_vec.push(sum_check_oracle.clone());
    }
    sum_check_oracles_vec
}
#[test]
fn time_sumcheck() {
    let i = 23;
    let mut rng = ChaCha8Rng::from_entropy();
    let evals = Type1Polynomial {
        poly: rand_vec::<Mersenne127>((1 << i), &mut rng),
    };
    let point = rand_vec::<Mersenne127>(i, &mut rng);
    let mut eq = build_eq_x_r_vec::<Mersenne127>(&point).unwrap();
    let now = Instant::now();
    (0..60).into_par_iter().for_each(|x| {


        let oracles = sum_check(evals.clone(), point.clone(), i, i, eq.clone());
    });
    println!("now.elased() {:?}", now.elapsed());
}

pub fn sum_check_challenge_round<F: PrimeField>(
    mut eq: &mut Type1Polynomial<F>,
    mut bh_values: &mut Type1Polynomial<F>,
    challenge: F,
) -> Vec<F> {
    one_level_eval_hc(&mut bh_values, challenge);
    one_level_eval_hc(&mut eq, challenge);

    one_level_interp_hc(&mut eq);
    one_level_interp_hc(&mut bh_values);

    //    parallel_pi(&bh_values, &eq)
    p_i(&bh_values, &eq)
}

fn basefold_one_round_by_interpolation_weights<F: PrimeField>(
    table: &Vec<Vec<(F, F)>>,
    table_offset: usize,
    values: &Type1Polynomial<F>,
    challenge: F,
) -> Type1Polynomial<F> {
    let level = &table[table.len() - 1 - table_offset];
    let fold = values
        .poly
        .par_chunks_exact(2)
        .enumerate()
        .map(|(i, ys)| {
            interpolate2_weights::<F>(
                [(level[i].0, ys[0]), (-(level[i].0), ys[1])],
                level[i].1,
                challenge,
            )
        })
        .collect::<Vec<_>>();
    Type1Polynomial { poly: fold }
}

fn basefold_one_round_by_interpolation_weights_not_faster<F: PrimeField>(
    table: &Vec<Vec<(F, F)>>,
    table_offset: usize,
    values: &Vec<F>,
    challenge: F,
) -> Vec<F> {
    let level = &table[table.len() - 1 - table_offset];
    let mut new_values = vec![F::ZERO; values.len() >> 1];
    new_values.par_iter_mut().enumerate().for_each(|(i, v)| {
        *v = interpolate2_weights::<F>(
            [
                (level[i].0, values[2 * i]),
                (-(level[i].0), values[2 * i + 1]),
            ],
            level[i].1,
            challenge,
        )
    });
    new_values
}

fn basefold_get_query<F: PrimeField>(
    first_oracle: &Type1Polynomial<F>,
    oracles: &Vec<Type1Polynomial<F>>,
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
    queries.push((first_oracle.poly[p0], first_oracle.poly[p1]));
    indices.push(p0);
    x_index >>= 1;

    for oracle in oracles {
        let mut p0 = x_index;
        let mut p1 = x_index ^ 1;
        if (p1 < p0) {
            p0 = x_index ^ 1;
            p1 = x_index;
        }
        queries.push((oracle.poly[p0], oracle.poly[p1]));
        indices.push(p0);
        x_index >>= 1;
    }

    return (queries, indices);
}

pub fn get_merkle_path<H: Hash, F: PrimeField>(
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
    block_length: usize,
    eval_index: usize,
    mut rng: &mut ChaCha8Rng,
    level: usize,
    mut cipher: &mut ctr::Ctr32LE<aes::Aes128>,
) -> F {
    let level_index = eval_index % (block_length);
    let mut el = query_root_table_from_rng_aes::<F>(
        level,
        (level_index % (block_length >> 1)),
        &mut rng,
        &mut cipher,
    );

    if level_index >= (block_length >> 1) {
        el = -F::ONE * el;
    }

    return el;
}
pub fn query_root_table_from_rng<F: PrimeField>(
    level: usize,
    index: usize,
    rng: &mut ChaCha8Rng,
) -> F {
    let mut level_offset: u128 = 1;
    for lg_m in 1..=level {
        let half_m = 1 << (lg_m - 1);
        level_offset += half_m;
    }
    //this is 512  because of the implementation of random in the ff rust library
    //    let pos = ((level_offset + (index as u128)) * (512))
    let pos = ((level_offset + (index as u128))
        * ((F::NUM_BITS as usize).next_power_of_two() as u128))
        .checked_div(32)
        .unwrap();

    rng.set_word_pos(pos);

    let res = rand_chacha::<F>(rng);

    res
}

pub fn query_root_table_from_rng_aes<F: PrimeField>(
    level: usize,
    index: usize,
    rng: &mut ChaCha8Rng,
    cipher: &mut ctr::Ctr32LE<aes::Aes128>,
) -> F {
    let mut level_offset: u128 = 1;
    for lg_m in 1..=level {
        let half_m = 1 << (lg_m - 1);
        level_offset += half_m;
    }

    let pos = ((level_offset + (index as u128))
        * ((F::NUM_BITS as usize).next_power_of_two() as u128))
        .checked_div(8)
        .unwrap();

    cipher.seek(pos);

    let bytes = (F::NUM_BITS as usize).next_power_of_two() / 8;
    let mut dest: Vec<u8> = vec![0u8; bytes];
    cipher.apply_keystream(&mut dest);

    let res = from_raw_bytes::<F>(&dest);

    res
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

pub fn multilinear_evaluation_ztoa<F: PrimeField>(poly: &mut Type2Polynomial<F>, point: &Vec<F>) {
    reverse_index_bits_in_place(&mut poly.poly);
    let n = log2_strict(poly.poly.len());
    for p in point {
        poly.poly.par_chunks_mut(2).for_each(|chunk| {
            chunk[0] = chunk[0] + *p * chunk[1];
            chunk[1] = chunk[0];
        });
        poly.poly = poly
            .poly
            .iter()
            .enumerate()
            .filter(|(i, e)| i % 2 == 0)
            .map(|(i, e)| *e)
            .collect::<Vec<F>>();
    }
    reverse_index_bits_in_place(&mut poly.poly);
}

pub fn multilinear_evaluation_atoz<F: PrimeField>(poly: &mut Vec<F>, point: &Vec<F>) {
    let n = log2_strict(poly.len());
    //    assert_eq!(point.len(),n);
    for p in point {
        poly.par_chunks_mut(2).for_each(|chunk| {
            chunk[0] = *p * chunk[0] + chunk[1];
            chunk[1] = chunk[0];
        });
        poly.dedup();
    }
}
#[test]
fn bench_multilinear_eval() {
    use crate::util::ff_255::ff255::Ft255;
    for i in 10..27 {
        let mut rng = ChaCha8Rng::from_entropy();
        let mut poly = Type2Polynomial {
            poly: rand_vec::<Ft255>(1 << i, &mut rng),
        };
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
    use crate::util::transcript::{
        FieldTranscript, FieldTranscriptRead, FieldTranscriptWrite, InMemoryTranscript,
        TranscriptRead, TranscriptWrite,
    };

    use crate::{
        pcs::multilinear::{
            basefold::{
                basefold_one_round_by_interpolation_weights, encode_repetition_basecode,
                encode_rs_basecode, evaluate_over_foldable_domain, evaluate_over_foldable_domain_2,
                evaluate_over_foldable_domain_generic_basecode, get_table_aes,
                interpolate_over_boolean_hypercube_with_copy, log2_strict,
                multilinear_evaluation_atoz, multilinear_evaluation_ztoa, one_level_eval_hc,
                one_level_interp_hc, rand_chacha, Basefold, Type1Polynomial, Type2Polynomial,
            },
            test::{run_batch_commit_open_verify, run_commit_open_verify},
        },
        poly::{multilinear::MultilinearPolynomial, Polynomial},
        util::{
            hash::{Hash, Keccak256, Output},
            new_fields::{Mersenne127, Mersenne61},
            play_field::PlayField,
            transcript::{Blake2sTranscript, Keccak256Transcript},
        },
    };
    use halo2_curves::{ff::Field, secp256k1::Fp};
    use plonky2_util::reverse_index_bits_in_place;
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha12Rng, ChaCha8Rng,
    };
    use std::io;

    use crate::pcs::multilinear::basefold::Instant;
    use crate::pcs::multilinear::BasefoldExtParams;
    use crate::util::arithmetic::PrimeField;
    use blake2::{digest::FixedOutputReset, Blake2s256};
    use halo2_curves::bn256::{Bn256, Fr};

    type Pcs = Basefold<Fr, Blake2s256, Five>;

    #[derive(Debug)]
    pub struct Five {}

    impl BasefoldExtParams for Five {
        fn get_reps() -> usize {
            return 33;
        }

        fn get_rate() -> usize {
            return 3;
        }

        fn get_basecode_rounds() -> usize {
            return 0;
        }
        fn get_rs_basecode() -> bool {
            false
        }
    }

    #[test]
    fn test_transforms() {
        type F = Mersenne127;
        use rand::rngs::OsRng;
        let num_vars = 10;
        let log_rate = 1;
        let poly = MultilinearPolynomial::<F>::rand(num_vars, OsRng);
        let mut rng = ChaCha8Rng::from_entropy();

        let (mut table_w_weights, mut table) = get_table_aes((1 << num_vars), log_rate, &mut rng);
        let (mut coeffs, mut bh_evals) =
            interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
                poly: poly.evals().to_vec(),
            });

        let mut commitment = evaluate_over_foldable_domain(log_rate, coeffs.clone(), &table);

        let challenge = rand_chacha::<F>(&mut rng);
        let fold = basefold_one_round_by_interpolation_weights(
            &table_w_weights,
            0,
            &commitment,
            challenge,
        );

        let chal_vec = vec![challenge];
        let partial_eval = multilinear_evaluation_ztoa(&mut coeffs, &chal_vec);

        let mut commitment = evaluate_over_foldable_domain(log_rate, coeffs.clone(), &table);

        assert_eq!(commitment, fold);

        //fold bh_evals one level
        one_level_interp_hc(&mut bh_evals);
        one_level_eval_hc(&mut bh_evals, challenge);

        //convert bh_evals to type2
        reverse_index_bits_in_place(&mut bh_evals.poly);

        let bh_evals = Type2Polynomial {
            poly: bh_evals.poly,
        };
        let (bhcoeffs, mut bh_evals) = interpolate_over_boolean_hypercube_with_copy(&bh_evals);

        //coeffs is type2, partial eval is also type2
        assert_eq!(coeffs, bhcoeffs);
    }
    #[test]
    fn test_rs_transform() {
        type F = Mersenne127;
        use rand::rngs::OsRng;
        let num_vars = 10;
        let log_rate = 1;
        let num_rounds = 1;
        let poly = MultilinearPolynomial::<F>::rand(num_vars, OsRng);
        let mut rng = ChaCha8Rng::from_entropy();

        let (mut table_w_weights, mut table) = get_table_aes((1 << num_vars), log_rate, &mut rng);
        let (mut coeffs_og, mut bh_evals) =
            interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
                poly: poly.evals().to_vec(),
            });

        //coeffs is type2, bh_evals is type 1, basecode will have type2
        let mut coeffs =
            encode_rs_basecode(&coeffs_og, 1 << log_rate, 1 << (num_vars - num_rounds));

        let log_chunk = num_vars - num_rounds;
        let mut commitment = evaluate_over_foldable_domain_2(
            num_vars - num_rounds + log_rate,
            log_rate,
            coeffs.clone(),
            &table,
        );

        let challenge = rand_chacha::<F>(&mut rng);
        let mut fold = basefold_one_round_by_interpolation_weights(
            &table_w_weights,
            0,
            &commitment,
            challenge,
        );

        let chal_vec = vec![challenge];

        one_level_interp_hc(&mut bh_evals);
        one_level_eval_hc(&mut bh_evals, challenge);

        reverse_index_bits_in_place(&mut bh_evals.poly); //convert to type2

        let (mut new_coeffs, _) = interpolate_over_boolean_hypercube_with_copy(&Type2Polynomial {
            poly: bh_evals.poly,
        });

        let rs = encode_rs_basecode(&new_coeffs, 1 << log_rate, 1 << (num_vars - num_rounds));

        //Compare a partial eval of RS Evaluations to an RS Evaluation of a partial Eval

        //        let mut commitment = evaluate_over_foldable_domain_2(num_vars - num_rounds + log_rate, log_rate, rs.clone(), &table);
        reverse_index_bits_in_place(&mut fold.poly);
        assert_eq!(rs, Type2Polynomial { poly: fold.poly });
    }

    #[test]
    fn commit_open_verify() {
        run_commit_open_verify::<_, Pcs, Blake2sTranscript<_>>();
    }

    #[test]
    fn batch_commit_open_verify() {
        run_batch_commit_open_verify::<_, Pcs, Blake2sTranscript<_>>();
    }

    struct PretendHash {}
    #[test]
    fn test_sha3_hashes() {
        use blake2::digest::FixedOutputReset;

        type H = Keccak256;
        let lots_of_hashes = Instant::now();
        let values = vec![Mersenne127::ONE; 2000];
        let mut hashes = vec![Output::<H>::default(); (values.len() >> 1)];
        for (i, mut hash) in hashes.iter_mut().enumerate() {
            let mut hasher = H::new();
            hasher.update_field_element(&values[i + i]);
            hasher.update_field_element(&values[i + i + 1]);
            hasher.finalize_into_reset(&mut hash);
        }
        println!("lots of hashes sha3 time {:?}", lots_of_hashes.elapsed());

        let hash_alot = Instant::now();
        let mut hasher = H::new();
        for i in 0..2000 {
            hasher.update_field_element(&values[i]);
        }
        let mut hash = Output::<H>::default();
        hasher.finalize_into_reset(&mut hash);
        println!("hash a lot sha3 time {:?}", hash_alot.elapsed());
    }

    #[test]
    fn test_blake2b_hashes() {
        use blake2::{digest::FixedOutputReset, Blake2b512, Blake2s256};

        type H = Blake2s256;
        let lots_of_hashes = Instant::now();
        let values = vec![Mersenne127::ONE; 2000];
        let mut hashes = vec![Output::<H>::default(); (values.len() >> 1)];
        for (i, mut hash) in hashes.iter_mut().enumerate() {
            let mut hasher = H::new();
            hasher.update_field_element(&values[i + i]);
            hasher.update_field_element(&values[i + i + 1]);
            hasher.finalize_into_reset(&mut hash);
        }
        println!("lots of hashes blake2 time {:?}", lots_of_hashes.elapsed());

        let hash_alot = Instant::now();
        let mut hasher = H::new();
        for i in 0..2000 {
            hasher.update_field_element(&values[i]);
        }
        let mut hash = Output::<H>::default();
        hasher.finalize_into_reset(&mut hash);
        println!("hash alot blake2 time {:?}", hash_alot.elapsed());
    }

    #[test]
    fn test_blake2b_no_finalize() {
        use blake2::{digest::FixedOutputReset, Blake2b512, Blake2s256};

        type H = Blake2s256;
        let lots_of_hashes = Instant::now();
        let values = vec![Mersenne127::ONE; 2000];
        let mut hashes = vec![Output::<H>::default(); (values.len() >> 1)];
        for (i, mut hash) in hashes.iter_mut().enumerate() {
            let mut hasher = H::new();
            let f1 = values[i + 1].to_repr();
            let f2 = values[i + i + 1].to_repr();
            let data = [f1.as_ref(), f2.as_ref()].concat();
            //	    hasher.update_field_element(&values[i + i]);
            //	    hasher.update_field_element(&values[i+ i + 1]);
            *hash = H::digest(&data);
        }
        println!(
            "lots of hashes blake2 time no finalize{:?}",
            lots_of_hashes.elapsed()
        );

        let hash_alot = Instant::now();
        let mut hasher = H::new();
        for i in 0..2000 {
            hasher.update_field_element(&values[i]);
        }
        let mut hash = Output::<H>::default();
        hasher.finalize_into_reset(&mut hash);
        println!("hash alot blake2 time no finalize{:?}", hash_alot.elapsed());
    }

    #[test]
    fn test_cipher() {
        use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use generic_array::GenericArray;
        use hex_literal::hex;
        type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;
        let mut rng = ChaCha12Rng::from_entropy();

        let mut key: [u8; 16] = [042; 16];
        let mut iv: [u8; 16] = [024; 16];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);
        //	rng.set_word_pos(0);

        let mut key2: [u8; 16] = [042; 16];
        let mut iv2: [u8; 16] = [024; 16];
        rng.fill_bytes(&mut key2);
        rng.fill_bytes(&mut iv2);

        let plaintext = *b"hello world! this is my plaintext.";
        let ciphertext =
            hex!("3357121ebb5a29468bd861467596ce3da59bdee42dcc0614dea955368d8a5dc0cad4");
        let mut buf = plaintext.to_vec();
        let mut buf1 = [0u8; 100];

        let mut cipher = Aes128Ctr64LE::new(
            GenericArray::from_slice(&key[..]),
            GenericArray::from_slice(&iv[..]),
        );
        let hash_time = Instant::now();
        cipher.apply_keystream(&mut buf1[..]);
        println!("aes hash 34 bytes {:?}", hash_time.elapsed());
        println!("buf1 {:?}", buf1);
        for i in 0..40 {
            let now = Instant::now();
            cipher.seek((1 << i) as u64);
            println!("aes seek {:?} : {:?}", (1 << i), now.elapsed());
        }
        let mut bufnew = [0u8; 1];
        cipher.apply_keystream(&mut bufnew);

        println!("byte1 {:?}", bufnew);

        /*
            let mut cipher2 = Aes128Ctr64LE::new(&key.into(),&iv.into());
            let mut buf2 = [0u8; 34];
            for chunk in buf2.chunks_mut(3){
                cipher2.apply_keystream(chunk);
            }

            assert_eq!(buf1,buf2);
        */
        let mut dest: Vec<u8> = vec![0u8; 34];
        let mut rng = ChaCha8Rng::from_entropy();
        let now = Instant::now();
        rng.fill_bytes(&mut dest);
        println!("chacha20 hash 34 bytes {:?}", now.elapsed());
        println!("des {:?}", dest);
        let now = Instant::now();
        rng.set_word_pos(1);

        println!("chacha8 seek {:?}", now.elapsed());

        let mut cipher = Aes128Ctr64LE::new(
            GenericArray::from_slice(&key[..]),
            GenericArray::from_slice(&iv[..]),
        );
        let mut buf2 = vec![0u8; 34];
        let hash_time = Instant::now();

        let now = Instant::now();
        cipher.seek(33u64);
        println!("aes seek {:?}", now.elapsed());
        let mut bufnew = [0u8; 1];
        cipher.apply_keystream(&mut bufnew);

        println!("byte1 {:?}", bufnew);
    }

    #[test]
    fn test_blake2b_simd_hashes() {
        use blake2b_simd::{blake2b, many::update_many, State};
        use ff::PrimeField;
        let lots_of_hashes = Instant::now();
        let values = vec![Mersenne127::ONE; 2000];
        let mut states = vec![State::new(); 1000];

        for (i, mut hash) in states.iter_mut().enumerate() {
            hash.update(&values[i + i].to_repr().as_ref());
            hash.update(&values[i + i + 1].to_repr().as_ref());
            hash.finalize();
        }
        println!(
            "lots of hashes blake2simd time {:?}",
            lots_of_hashes.elapsed()
        );

        let hash_alot = Instant::now();
        let mut state = State::new();
        for i in 0..2000 {
            state.update(values[i].to_repr().as_ref());
        }
        let hash = state.finalize();
        println!("hash alot blake2simd time {:?}", hash_alot.elapsed());
    }
}

fn reed_solomon_into<F: Field>(input: &[F], mut target: impl AsMut<[F]>, domain: &Vec<F>) {
    target
        .as_mut()
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, target)| *target = horner(input, &domain[i]));
}

fn virtual_open<F: PrimeField>(
    num_vars: usize,
    num_rounds: usize,
    eq: &mut Type1Polynomial<F>,
    bh_evals: &mut Type1Polynomial<F>,
    last_oracle: &Type1Polynomial<F>,
    point: &Vec<F>,
    challenges: &mut Vec<F>,
    table: &Vec<Vec<(F, F)>>,
    sum_check_oracles: &mut Vec<Vec<F>>,
) {
    let mut rng = ChaCha8Rng::from_entropy();
    let rounds = num_vars - num_rounds;

    let mut oracles = Vec::with_capacity(rounds);
    let mut new_oracle = last_oracle;
    for round in 0..rounds {
        let challenge: F = rand_chacha(&mut rng);
        challenges.push(challenge);

        sum_check_oracles.push(sum_check_challenge_round(eq, bh_evals, challenge));

        oracles.push(basefold_one_round_by_interpolation_weights::<F>(
            &table,
            round + num_rounds,
            &new_oracle,
            challenge,
        ));
        new_oracle = &oracles[round];
    }

    let mut no = new_oracle.clone();
    no.poly.dedup();

    //verify it information-theoretically
    let mut eq_r_ = F::ONE;
    for i in 0..challenges.len() {
        eq_r_ = eq_r_ * (challenges[i] * point[i] + (F::ONE - challenges[i]) * (F::ONE - point[i]));
    }
    let last_challenge = challenges[challenges.len() - 1];

    assert_eq!(
        degree_2_eval(&sum_check_oracles[challenges.len() - 1], last_challenge),
        eq_r_ * no.poly[0]
    );
}
//outputs (trees, sumcheck_oracles, oracles, bh_evals, eq, eval)
fn commit_phase<F: PrimeField, H: Hash>(
    point: &Point<F, MultilinearPolynomial<F>>,
    comm: &BasefoldCommitment<F, H>,
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
    num_vars: usize,
    num_rounds: usize,
    table_w_weights: &Vec<Vec<(F, F)>>,
) -> (
    Vec<Vec<Vec<Output<H>>>>,
    Vec<Vec<F>>,
    Vec<Type1Polynomial<F>>,
    Type1Polynomial<F>,
    Type1Polynomial<F>,
    F,
) {
    let mut oracles = Vec::with_capacity(num_vars);

    let mut trees = Vec::with_capacity(num_vars);

    let mut new_tree = &comm.codeword_tree;
    let mut root = new_tree[new_tree.len() - 1][0].clone();
    let mut new_oracle = &comm.codeword;

    let num_rounds = num_rounds;

    let mut eq = build_eq_x_r_vec::<F>(&point).unwrap();
    let mut eval = F::ZERO;
    let mut bh_evals = Type1Polynomial {
        poly: Vec::with_capacity(1 << num_vars),
    };
    for i in 0..eq.len() {
        eval = eval + comm.bh_evals.poly[i] * eq[i];
        bh_evals.poly.push(comm.bh_evals.poly[i]);
    }

    let mut eq = Type1Polynomial { poly: eq };
    let mut sum_check_oracles_vec = Vec::with_capacity(num_rounds + 1);
    let mut sum_check_oracle = sum_check_first_round::<F>(&mut eq, &mut bh_evals);
    sum_check_oracles_vec.push(sum_check_oracle.clone());

    for i in 0..(num_rounds) {
        transcript.write_commitment(&root).unwrap();
        transcript.write_field_elements(&sum_check_oracle);

        let challenge: F = transcript.squeeze_challenge();

        sum_check_oracle = sum_check_challenge_round(&mut eq, &mut bh_evals, challenge);

        sum_check_oracles_vec.push(sum_check_oracle.clone());

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
    transcript.write_field_elements(&sum_check_oracle);
    return (trees, sum_check_oracles_vec, oracles, bh_evals, eq, eval);
}

fn query_phase<F: PrimeField, H: Hash>(
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
    comm: &BasefoldCommitment<F, H>,
    oracles: &Vec<Type1Polynomial<F>>,
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
            ((x_int as usize) % comm.codeword.poly.len()).into()
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

fn verifier_query_phase<F: PrimeField, H: Hash>(
    query_challenges: &Vec<F>,
    query_merkle_paths: &Vec<Vec<Vec<Vec<Output<H>>>>>,
    sum_check_oracles: &Vec<Vec<F>>,
    fold_challenges: &Vec<F>,
    queries: &Vec<Vec<&[F]>>,
    num_rounds: usize,
    num_vars: usize,
    log_rate: usize,
    roots: &Vec<Output<H>>,
    rng: ChaCha8Rng,
    eval: &F,
) -> Vec<usize> {
    let n = (1 << (num_vars + log_rate));
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
    let mut key: [u8; 16] = [0u8; 16];
    let mut iv: [u8; 16] = [0u8; 16];
    let mut rng = rng.clone();
    rng.set_word_pos(0);
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new(
        GenericArray::from_slice(&key[..]),
        GenericArray::from_slice(&iv[..]),
    );
    queries_usize
        .par_iter_mut()
        .enumerate()
        .for_each(|(qi, query_index)| {
            let mut cipher = cipher.clone();
            let mut rng = rng.clone();
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
                let x0: F = query_point(
                    1 << (num_vars + log_rate - i),
                    ri0,
                    &mut rng,
                    num_vars + log_rate - i - 1,
                    &mut cipher,
                );
                let x1 = -x0;

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

    assert_eq!(eval, &degree_2_zero_plus_one(&sum_check_oracles[0]));

    for i in 0..fold_challenges.len() - 1 {
        assert_eq!(
            degree_2_eval(&sum_check_oracles[i], fold_challenges[i]),
            degree_2_zero_plus_one(&sum_check_oracles[i + 1])
        );
    }
    return queries_usize;
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

fn get_table<F: PrimeField>(
    poly_size: usize,
    rate: usize,
    rng: &mut ChaCha8Rng,
) -> (Vec<Vec<(F, F)>>, Vec<Vec<F>>) {
    let lg_n: usize = rate + log2_strict(poly_size);

    let now = Instant::now();

    let bytes = (F::NUM_BITS as usize).next_power_of_two() * (1 << lg_n) / 8;
    let mut dest: Vec<u8> = vec![0u8; bytes];
    rng.fill_bytes(&mut dest);

    let flat_table: Vec<F> = dest
        .par_chunks_exact((F::NUM_BITS as usize).next_power_of_two() / 8)
        .map(|chunk| from_raw_bytes::<F>(&chunk.to_vec()))
        .collect::<Vec<_>>();

    assert_eq!(flat_table.len(), 1 << lg_n);

    let mut weights: Vec<F> = flat_table
        .par_iter()
        .map(|el| F::ZERO - *el - *el)
        .collect();

    let mut scratch_space = vec![F::ZERO; weights.len()];
    BatchInverter::invert_with_external_scratch(&mut weights, &mut scratch_space);

    let mut flat_table_w_weights = flat_table
        .iter()
        .zip(weights)
        .map(|(el, w)| (*el, w))
        .collect_vec();

    let mut unflattened_table_w_weights = vec![Vec::new(); lg_n];
    let mut unflattened_table = vec![Vec::new(); lg_n];

    let mut level_weights = flat_table_w_weights[0..2].to_vec();
    reverse_index_bits_in_place(&mut level_weights);
    unflattened_table_w_weights[0] = level_weights;

    unflattened_table[0] = flat_table[0..2].to_vec();
    for i in 1..lg_n {
        unflattened_table[i] = flat_table[(1 << i)..(1 << (i + 1))].to_vec();
        let mut level = flat_table_w_weights[(1 << i)..(1 << (i + 1))].to_vec();
        reverse_index_bits_in_place(&mut level);
        unflattened_table_w_weights[i] = level;
    }

    return (unflattened_table_w_weights, unflattened_table);
}

fn get_table_aes<F: PrimeField>(
    poly_size: usize,
    rate: usize,
    rng: &mut ChaCha8Rng,
) -> (Vec<Vec<(F, F)>>, Vec<Vec<F>>) {
    let lg_n: usize = rate + log2_strict(poly_size);

    let now = Instant::now();

    let mut key: [u8; 16] = [0u8; 16];
    let mut iv: [u8; 16] = [0u8; 16];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    type Aes128Ctr64LE = ctr::Ctr32LE<aes::Aes128>;

    let mut cipher = Aes128Ctr64LE::new(
        GenericArray::from_slice(&key[..]),
        GenericArray::from_slice(&iv[..]),
    );

    let bytes = (F::NUM_BITS as usize).next_power_of_two() * (1 << lg_n) / 8;
    let mut dest: Vec<u8> = vec![0u8; bytes];
    cipher.apply_keystream(&mut dest[..]);

    let flat_table: Vec<F> = dest
        .par_chunks_exact((F::NUM_BITS as usize).next_power_of_two() / 8)
        .map(|chunk| from_raw_bytes::<F>(&chunk.to_vec()))
        .collect::<Vec<_>>();

    assert_eq!(flat_table.len(), 1 << lg_n);

    let mut weights: Vec<F> = flat_table
        .par_iter()
        .map(|el| F::ZERO - *el - *el)
        .collect();

    let mut scratch_space = vec![F::ZERO; weights.len()];
    BatchInverter::invert_with_external_scratch(&mut weights, &mut scratch_space);

    let mut flat_table_w_weights = flat_table
        .iter()
        .zip(weights)
        .map(|(el, w)| (*el, w))
        .collect_vec();

    let mut unflattened_table_w_weights = vec![Vec::new(); lg_n];
    let mut unflattened_table = vec![Vec::new(); lg_n];

    let mut level_weights = flat_table_w_weights[0..2].to_vec();
    reverse_index_bits_in_place(&mut level_weights);
    unflattened_table_w_weights[0] = level_weights;

    unflattened_table[0] = flat_table[0..2].to_vec();
    for i in 1..lg_n {
        unflattened_table[i] = flat_table[(1 << i)..(1 << (i + 1))].to_vec();
        let mut level = flat_table_w_weights[(1 << i)..(1 << (i + 1))].to_vec();
        reverse_index_bits_in_place(&mut level);
        unflattened_table_w_weights[i] = level;
    }

    return (unflattened_table_w_weights, unflattened_table);
}
