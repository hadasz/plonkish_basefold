use rand::rngs::OsRng;
use benchmark::{
    espresso,
    halo2::{AggregationCircuit, Sha256Circuit},
    BasefoldParams::*    
};

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
    poly::multilinear::{MultilinearPolynomial},
    backend::{self, PlonkishBackend, PlonkishCircuit},
    frontend::halo2::{circuit::VanillaPlonk, CircuitExt, Halo2Circuit},
    halo2_curves::{bn256::{Bn256, Fr}, secp256k1::Fp},
    pcs::{PolynomialCommitmentScheme, multilinear::{MultilinearKzg,Basefold,MultilinearBrakedown, ZeromorphFri, BasefoldExtParams }, univariate::Fri},
    util::{
        end_timer, start_timer,
        test::std_rng,
        transcript::{InMemoryTranscript, Blake2sTranscript, Keccak256Transcript, TranscriptRead, TranscriptWrite, Blake2s256Transcript},
	hash::{Keccak256,Blake2s256,Blake2s},
	arithmetic::{PrimeField,sum},
	code::{BrakedownSpec6, BrakedownSpec1},
	new_fields::{Mersenne127, Mersenne61},
	mersenne_61_mont::Mersenne61Mont,
	ff_255::{ff255::Ft255, ft127::Ft127, ft63::Ft63},
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


const OUTPUT_DIR: &str = "./bench_data/pcs";
use std::env;

#[derive(Debug)]
struct P {}

impl BasefoldExtParams for P{

    fn get_rate() -> usize{
	return 2;
    }

    fn get_basecode() -> usize{
	return 2;
    }

    fn get_reps() -> usize{
	return 1000;
    }
}
fn main() {
    let (systems,  k_range) = parse_args();
    create_output(&systems);
    k_range.for_each(|k| systems.iter().for_each(|system| system.bench(k)));
}

fn bench_pcs<F, Pcs, T>(k: usize, pcs : System )
where
   F: PrimeField,
   Pcs: PolynomialCommitmentScheme<F, Polynomial = MultilinearPolynomial<F>>,
   T: TranscriptRead<Pcs::CommitmentChunk, F>
        + TranscriptWrite<Pcs::CommitmentChunk, F>
        + InMemoryTranscript<Param = ()>,

{
    let timer = start_timer(|| format!("PCS setup and trim -{k}"));
    let mut rng = OsRng;
    let poly_size = 1 << k;
    let param = Pcs::setup(poly_size, 1, &mut rng).unwrap();
    let trim_t = Instant::now();
    let (pp,vp) = Pcs::trim(&param, poly_size, 1).unwrap();



    let timer = start_timer(|| format!("commit -{k}"));
    let mut transcript = T::new(());

    let poly = MultilinearPolynomial::rand(k,OsRng);

    let sample_size = sample_size(k);

    let mut commit_times = Vec::new();
    let mut times = Vec::new();
    for i in 0..sample_size{

	let cstart = Instant::now();
	let comm = Pcs::commit_and_write(&pp, &poly, &mut transcript).unwrap();
	
	commit_times.push(cstart.elapsed());

	let start = Instant::now();
	let point = transcript.squeeze_challenges(k);
	let eval = poly.evaluate(point.as_slice());
	transcript.write_field_element(&eval).unwrap();	
	Pcs::open(&pp, &poly, &comm, &point, &eval, &mut transcript).unwrap();
	times.push(start.elapsed());
    }
    let sum = times.iter().sum::<Duration>();
    let csum = commit_times.iter().sum::<Duration>();
    
    let avg = sum / sample_size as u32;
    let cavg = csum /sample_size as u32;

    
    writeln!(&mut pcs.commit_output(), "{k}, {}", cavg.as_millis()).unwrap();
    writeln!(&mut pcs.output(), "{k}, {}", avg.as_millis()).unwrap();    
    
    let proof = transcript.into_proof();




    let timer = start_timer(|| format!("verify-{k}"));
    let result = {
	let mut transcript = T::from_proof((),proof.as_slice());
	let mut start_size = 0;
	while(transcript.read_commitment().is_ok()){
	    start_size = start_size + 1;
	}

	let mut transcript = T::from_proof((),proof.as_slice());
	let now = Instant::now();
	let b = Pcs::verify(
            &vp,
            &Pcs::read_commitment(&vp, &mut transcript).unwrap(),
            &transcript.squeeze_challenges(k),
            &transcript.read_field_element().unwrap(),
            &mut transcript
	);
	writeln!(&mut pcs.verify_output(), "{:?}: {:?}", k, now.elapsed().as_millis()).unwrap();
	let mut end_size = 0;
	while(transcript.read_commitment().is_ok()){
	    end_size = end_size + 1;
	}
	writeln!(&mut pcs.size_output(), "{:?} {:?} : {:?}", pcs, k, (start_size - end_size)*256);
	b
    };

    end_timer(timer);
    assert_eq!(result,Ok(()));
}




#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum System {
    MultilinearKzg,
    Basefold256,
    Basefold61Mersenne,
    BasefoldBlake2s,
    Brakedown,
    BrakedownBlake2s,
    ZeromorphFri
}

impl System {
    fn all() -> Vec<System> {
        vec![
            System::MultilinearKzg,
	    System::Basefold61Mersenne,
	    System::Basefold256,
	    System::Brakedown,
	    System::BasefoldBlake2s,
	    System::BrakedownBlake2s,
	    System::ZeromorphFri
	    
	
        ]
    }

    fn output_path(&self) -> String {
        format!("{OUTPUT_DIR}/open_{self}")
    }

    fn output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.output_path())
            .unwrap()
    }

    fn commit_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/commit_{self}")
    }

    fn size_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/size_{self}")
    }

    fn verify_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/verify_{self}")
    }    

    fn commit_output(&self) -> File {

        OpenOptions::new()
            .append(true)
            .open(self.commit_output_path())
            .unwrap()
    }

    fn size_output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.size_output_path())
            .unwrap()
    }


    fn verify_output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.verify_output_path())
            .unwrap()
    }        


    fn bench(&self, k: usize) {
	type Kzg = MultilinearKzg<Bn256>;
	type Brakedown = MultilinearBrakedown<Fp, Keccak256, BrakedownSpec6>;
	type Brakedown127 = MultilinearBrakedown<Fp, Blake2s, BrakedownSpec6>;	
	type BrakedownBlake2s = MultilinearBrakedown<GoldilocksMont, Blake2s, BrakedownSpec1>;		

        match self {
	    System::MultilinearKzg => bench_pcs::<_, Kzg, Blake2sTranscript<_>>(k, System::MultilinearKzg),
	    System::Basefold61Mersenne => bench_pcs::<Mersenne127, Basefold<Mersenne127,Blake2s,P>, Blake2sTranscript<_>>(k, System::Basefold61Mersenne),
	    System::Basefold256 => bench_pcs::<Fr, Basefold<Fr,Blake2s256,BasefoldFri>, Blake2s256Transcript<_>>(k, System::Basefold256),	    
	    System::Brakedown => bench_pcs::<Fp, Brakedown, Keccak256Transcript<_>>(k,System::Brakedown),
	    System::BasefoldBlake2s => {
	    match k {
	    	  10 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,Ten>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  11 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,Eleven>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  12 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,Twelve>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  13 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,Thirteen>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  14 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,Fourteen>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  15 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,Fifteen>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  16 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,Sixteen>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  17 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,Seventeen>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  18 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,Eighteen>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  19 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,Nineteen>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  20 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,Twenty>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  21 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,TwentyOne>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  22 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,TwentyTwo>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  23 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,TwentyThree>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  24 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,TwentyFour>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  25 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,TwentyFive>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),
		  26 => bench_pcs::<GoldilocksMont, Basefold<GoldilocksMont,Blake2s,TwentySix>, Blake2sTranscript<_>>(k,System::BasefoldBlake2s),		  
		  _ => {}
		   }
	    }
	    System::BrakedownBlake2s => bench_pcs::<GoldilocksMont, BrakedownBlake2s, Blake2sTranscript<_>>(k,System::BrakedownBlake2s),
	    System::ZeromorphFri => bench_pcs::<Fr, ZeromorphFri<Fri<Fr,Blake2s>>, Blake2sTranscript<_>>(k, System::ZeromorphFri)
            
	}
    }
}

impl Display for System {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            System::Basefold256 => write!(f, "basefold256"),
	    System::Basefold61Mersenne => write!(f, "basefold61Mersenne"),
	    System::MultilinearKzg => write!(f, "kzg"),
	    System::Brakedown => write!(f, "brakedown"),
	    System::BrakedownBlake2s => write!(f,"brakedown_blake"),
	    System::BasefoldBlake2s => write!(f,"basefold_blake"),
	    System::ZeromorphFri => write!(f, "zeromorph_fri")
        }
    }
}




fn parse_args() -> (Vec<System>, Range<usize>) {
    let (systems, k_range) = args().chain(Some("".to_string())).tuple_windows().fold(
        (Vec::new(),  10..24),
        |(mut systems,  mut k_range), (key, value)| {
            match key.as_str() {
                "--system" => match value.as_str() {
                    "all" => systems = vec![System::BrakedownBlake2s,System::BasefoldBlake2s],
                    "basefold256" => systems.push(System::Basefold256),
                    "multilinearkzg" => systems.push(System::MultilinearKzg),		               _ => panic!(
                        "system should be one of {{all,hyperplonk,halo2,espresso_hyperplonk}}"
                    ),
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
            (vec![System::Basefold256], k_range)
        },
    );

    let mut systems = systems.into_iter().sorted().dedup().collect_vec();
    if systems.is_empty() {
        systems = System::all();
    };
    (systems,  k_range)
}

fn create_output(systems: &[System]) {
    if !Path::new(OUTPUT_DIR).exists() {
        create_dir(OUTPUT_DIR).unwrap();
    }
    for system in systems {
        File::create(system.output_path()).unwrap();
        File::create(system.commit_output_path()).unwrap();
        File::create(system.size_output_path()).unwrap();
        File::create(system.verify_output_path()).unwrap();			
    }
}

fn sample<T>(system: System, k: usize, prove: impl Fn() -> T) -> T {
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
    writeln!(&mut system.output(), "{k}, {}", avg.as_millis()).unwrap();
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

