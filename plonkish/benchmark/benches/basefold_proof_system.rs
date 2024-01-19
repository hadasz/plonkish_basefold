use benchmark::{
    espresso,
    halo2::{AggregationCircuit, Sha256Circuit},
    BasefoldParams::*
};
use espresso_hyperplonk::{prelude::MockCircuit, HyperPlonkSNARK};
use espresso_subroutines::{MultilinearKzgPCS, PolyIOP, PolynomialCommitmentScheme};
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::kzg::{
        commitment::ParamsKZG,
        multiopen::{ProverGWC, VerifierGWC},
        strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Blake2bWrite, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use itertools::Itertools;
use plonkish_backend::{
    backend::{self, PlonkishBackend, PlonkishCircuit},
    frontend::halo2::{circuit::VanillaPlonk, CircuitExt, Halo2Circuit},
    halo2_curves::{bn256::{Bn256, Fr}, secp256k1::Fp},
    pcs::multilinear,
    util::{
        end_timer, start_timer,
        test::std_rng,
        transcript::{InMemoryTranscript, Blake2sTranscript},
	hash::{Blake2s256,Blake2s},
	new_fields::{Mersenne127,Mersenne61},
	mersenne_61_mont::Mersenne61Mont,
	goldilocksMont::GoldilocksMont
    },
};

use std::{
    env::args,
    fmt::Display,
    fs::{create_dir, File, OpenOptions},
    io::Write,
    iter,
    ops::Range,
    path::Path,
    time::{Duration, Instant},
};
#[derive(Debug)]
struct P {}

impl plonkish_backend::pcs::multilinear::BasefoldExtParams for P{

    fn get_rate() -> usize{
	return 2;
    }

    fn get_basecode_rounds() -> usize{
	return 2;
    }

    fn get_rs_basecode() -> bool{
	true
    }

    fn get_reps() -> usize{
	return 1000;
    }
}
const OUTPUT_DIR: &str = "./bench_data/basefold_256_fri";


fn main() {
    let (systems, circuit, k_range) = parse_args();
    create_output(&systems);
    println!("systems {:?}", systems);
    k_range.for_each(|k| systems.iter().for_each(|system| system.bench(k, circuit)));
}
fn bench_hyperplonk_256<C: CircuitExt<Fr>>(k: usize) {
    type Basefold = multilinear::Basefold<Fr,Blake2s256,BasefoldFri>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}


fn bench_hyperplonk_10<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Ten>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}

fn bench_hyperplonk_11<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Eleven>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_12<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Twelve>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_13<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Thirteen>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_14<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Fourteen>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_15<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Fifteen>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_16<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Sixteen>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_17<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Seventeen>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_18<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Eighteen>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_19<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Nineteen>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_20<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Twenty>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_21<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,TwentyOne>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_22<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,TwentyTwo>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_23<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,TwentyThree>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_24<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,TwentyFour>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}

fn bench_hyperplonk_25<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,TwentyFive>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}

fn bench_hyperplonk_10_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Ten8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}

fn bench_hyperplonk_11_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Eleven8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_12_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Twelve8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_13_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Thirteen8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_14_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Fourteen8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_15_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Fifteen8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_16_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Sixteen8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_17_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Seventeen8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_18_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Eighteen8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_19_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Nineteen8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_20_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,Twenty8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_21_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,TwentyOne8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_22_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,TwentyTwo8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_23_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,TwentyThree8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}
fn bench_hyperplonk_24_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,TwentyFour8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}

fn bench_hyperplonk_25_8<C: CircuitExt<GoldilocksMont>>(k: usize) {
    type Basefold = multilinear::Basefold<GoldilocksMont,Blake2s256,TwentyFive8>;
    type HyperPlonk = backend::hyperplonk::HyperPlonk<Basefold>;

    let circuit = C::rand(k, std_rng());
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);



    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);


    let proof = sample(System::HyperPlonk, String::from("Fp - ecdsa"), k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        let mut transcript = Blake2sTranscript::default();
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        let proofs = transcript.into_proof();
	proofs
    });


    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, String::from("fp_vanilla"),k, || {
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });    


    let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
    let end_size = t1.into_proof().len();    

    writeln!(&mut (System::HyperPlonk).size_output(), "{k} : {:?}", (end_size)*8).unwrap();
    
    assert!(accept);
}





#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum System {
    HyperPlonk

}

impl System {
    fn all() -> Vec<System> {
        vec![
            System::HyperPlonk,
        ]
    }

    fn output_path(&self) -> String {
        format!("{OUTPUT_DIR}/hyperplonk-basefold")
    }

    fn output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.output_path())
            .unwrap()
    }

    fn verifier_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/{self}-kzg-verifier")
    }

    fn size_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/{self}-kzg-size")
    }

    fn size_output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.size_output_path())
            .unwrap()
    }
    fn verifier_output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.verifier_output_path())
            .unwrap()
    }    

    fn support(&self, circuit: Circuit) -> bool {
        match self {
            System::HyperPlonk => match circuit {
                Circuit::VanillaPlonk | Circuit::ECDSA | Circuit::Sha256 => true,
            },
        }
    }

    fn bench(&self, k: usize, circuit: Circuit) {
        if !self.support(circuit) {
            println!("skip benchmark on {circuit} with {self} because it's not compatible");
            return;
        }

        println!("start benchmark on 2^{k} {circuit} with {self}");

        match self {
            System::HyperPlonk => bench_hyperplonk_256::<VanillaPlonk<Fr>>(k),
/*
	    match k {
		10 => bench_hyperplonk_10_8::<VanillaPlonk<GoldilocksMont>>(k),
		11 => bench_hyperplonk_11_8::<VanillaPlonk<GoldilocksMont>>(k),
		12 => bench_hyperplonk_12_8::<VanillaPlonk<GoldilocksMont>>(k),
		13 => bench_hyperplonk_13_8::<VanillaPlonk<GoldilocksMont>>(k),
		14 => bench_hyperplonk_14_8::<VanillaPlonk<GoldilocksMont>>(k),
		15 => bench_hyperplonk_15_8::<VanillaPlonk<GoldilocksMont>>(k),
		16 => bench_hyperplonk_16_8::<VanillaPlonk<GoldilocksMont>>(k),
		17 => bench_hyperplonk_17_8::<VanillaPlonk<GoldilocksMont>>(k),
		18 => bench_hyperplonk_18_8::<VanillaPlonk<GoldilocksMont>>(k),
		19 => bench_hyperplonk_19_8::<VanillaPlonk<GoldilocksMont>>(k),
		20 => bench_hyperplonk_20_8::<VanillaPlonk<GoldilocksMont>>(k),
		21 => bench_hyperplonk_21_8::<VanillaPlonk<GoldilocksMont>>(k),
		22 => bench_hyperplonk_22_8::<VanillaPlonk<GoldilocksMont>>(k),
		23 => bench_hyperplonk_23_8::<VanillaPlonk<GoldilocksMont>>(k),
		24 => bench_hyperplonk_24_8::<VanillaPlonk<GoldilocksMont>>(k),
		25 => bench_hyperplonk_25_8::<VanillaPlonk<GoldilocksMont>>(k),						

	    _ => {}
            }
	    */
	}

    }
}


impl Display for System {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            System::HyperPlonk => write!(f, "hyperplonk"),

        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Circuit {
    VanillaPlonk,
    ECDSA,
    Sha256,
}

impl Circuit {
    fn min_k(&self) -> usize {
        match self {
            Circuit::VanillaPlonk => 4,
            Circuit::ECDSA => 4,
            Circuit::Sha256 => 17,
        }
    }
}

impl Display for Circuit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Circuit::VanillaPlonk => write!(f, "vanilla_plonk"),
            Circuit::ECDSA => write!(f, "ecdsa - fp"),
            Circuit::Sha256 => write!(f, "sha256"),
        }
    }
}

fn parse_args() -> (Vec<System>, Circuit, Range<usize>) {
    let (systems, circuit, k_range) = args().chain(Some("".to_string())).tuple_windows().fold(
        (Vec::new(), Circuit::ECDSA, 10..27),
        |(mut systems, mut circuit, mut k_range), (key, value)| {
            match key.as_str() {
                "--system" => match value.as_str() {
                    "all" => systems = System::all(),
                    "hyperplonk" => systems.push(System::HyperPlonk),
                    _ => panic!(
                        "system should be one of {{all,hyperplonk,halo2,espresso_hyperplonk}}"
                    ),
                },
                "--circuit" => match value.as_str() {
                    "vanilla_plonk" => circuit = Circuit::VanillaPlonk,
                    "aggregation" => circuit = Circuit::ECDSA,
                    "sha256" => circuit = Circuit::Sha256,
                    _ => panic!("circuit should be one of {{aggregation,vanilla_plonk}}"),
                },
                "--k" => {
                    if let Some((start, end)) = value.split_once("..") {
                        k_range = start.parse().expect("k range start to be usize")
                            ..end.parse().expect("k range end to be usize");
                    } else {
                        k_range.start = value.parse().expect("k to be usize");
                        k_range.end = k_range.start + 1;
                    }
                }
                _ => {}
            }
            (systems, circuit, k_range)
        },
    );
    if k_range.start < circuit.min_k() {
        panic!("k should be at least {} for {circuit:?}", circuit.min_k());
    }
    let mut systems = systems.into_iter().sorted().dedup().collect_vec();
    if systems.is_empty() {
        systems = System::all();
    };
    (systems, circuit, k_range)
}

fn create_output(systems: &[System]) {
    if !Path::new(OUTPUT_DIR).exists() {
        create_dir(OUTPUT_DIR).unwrap();
    }
    for system in systems {
        File::create(system.output_path()).unwrap();
        File::create(system.verifier_output_path()).unwrap();
        File::create(system.size_output_path()).unwrap();
    }
}

fn sample<T>(system: System, key:String, k: usize, prove: impl Fn() -> T) -> T {
    let mut proof = None;
    let sample_size = sample_size(k);
    let sum = iter::repeat_with(|| {
        let start = Instant::now();
        proof = Some(prove());
        start.elapsed()
    })
    .take(sample_size)
    .sum::<Duration>();
    let avg = sum / sample_size as u32;
    writeln!(&mut system.output(), "{k} : {}", avg.as_millis()).unwrap();
    println!("{}", avg.as_millis());
    proof.unwrap()
}

fn verifier_sample<T>(system: System, key:String, k: usize, prove: impl Fn() -> T) -> T {
    let mut proof = None;
    let sample_size = sample_size(k);
    let sum = iter::repeat_with(|| {
        let start = Instant::now();
        proof = Some(prove());
        start.elapsed()
    })
    .take(sample_size)
    .sum::<Duration>();
    let avg = sum / sample_size as u32;
    writeln!(&mut system.verifier_output(), "{k} : {}", avg.as_millis()).unwrap();
    proof.unwrap()
}

fn sample_size(k: usize) -> usize {
    if k < 16 {
        20
    } else if k < 20 {
        5
    } else {
        1
    }
}
