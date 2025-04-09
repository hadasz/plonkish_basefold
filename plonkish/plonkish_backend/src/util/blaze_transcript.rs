use std::time::Instant;
use num_traits::Zero;
use crate::util::avx_int_types::BlazeField;
use crate::{
    util::{
        arithmetic::{fe_mod_from_le_bytes, Coordinates, CurveAffine, PrimeField},
        hash::{Hash, Keccak256, Output, Update, Blake2s256, Blake2s},
        Itertools,
        transcript::{FieldTranscript, FieldTranscriptRead, FieldTranscriptWrite, Transcript, TranscriptRead, TranscriptWrite, InMemoryTranscript}
    },
    Error,
};

use std::{
    fmt::Debug,
    io::{self, Cursor},
};


pub type BlazeBlake2sTranscript<S> = BlazeFiatShamirTranscript<Blake2s, S>;


#[derive(Debug, Default)]
pub struct BlazeFiatShamirTranscript<H, S> {
    state: H,
    stream: S,
}

impl<H: Hash, F: BlazeField, S> FieldTranscript<F> for BlazeFiatShamirTranscript<H, S> {
    fn squeeze_challenge(&mut self) -> F {
        let hash = self.state.finalize_fixed_reset();
        self.state.update(&hash);
        F::from_hash(hash.as_slice())
    }

    fn common_field_element(&mut self, fe: &F) -> Result<(), Error> {
        self.state.update_blaze_field(fe);
        Ok(())
    }
}

impl<H: Hash, F: BlazeField, R: io::Read> FieldTranscriptRead<F> for BlazeFiatShamirTranscript<H, R> {
    fn read_field_element(&mut self) -> Result<F, Error> {
        let mut repr = <F as Zero>::zero().to_le_bytes();
        self.stream
            .read_exact(repr.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        repr.as_mut().reverse();
        let fe = F::from_le_bytes(repr);
        self.common_field_element(&fe)?;     
        Ok(fe)
    }
}

impl<H: Hash, F: BlazeField, W: io::Write> FieldTranscriptWrite<F> for BlazeFiatShamirTranscript<H, W> {
    fn write_field_element(&mut self, fe: &F) -> Result<(), Error> {
        self.common_field_element(fe)?;
        let mut repr = fe.to_le_bytes();
        repr.as_mut().reverse();
        self.stream
            .write_all(repr.as_ref())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))
    }
}



impl<H: Hash> InMemoryTranscript for BlazeFiatShamirTranscript<H, Cursor<Vec<u8>>> {
    type Param = ();

    fn new(_: Self::Param) -> Self {
        Self::default()
    }

    fn into_proof(self) -> Vec<u8> {
        self.stream.into_inner()
    }

    fn from_proof(_: Self::Param, proof: &[u8]) -> Self {
        Self {
            state: H::default(),
            stream: Cursor::new(proof.to_vec()),
        }
    }
}


impl<F: BlazeField, S> Transcript<Output<Blake2s>, F> for BlazeBlake2sTranscript<S> {
    fn common_commitment(&mut self, comm: &Output<Blake2s>) -> Result<(), Error> {
        self.state.update(comm);
        Ok(())
    }
}

impl<F: BlazeField, R: io::Read> TranscriptRead<Output<Blake2s>, F> for BlazeBlake2sTranscript<R> {
    fn read_commitment(&mut self) -> Result<Output<Blake2s>, Error> {
        let mut hash = Output::<Blake2s>::default();
        self.stream
            .read_exact(hash.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        Ok(hash)
    }
}

impl<F: BlazeField, W: io::Write> TranscriptWrite<Output<Blake2s>, F> for BlazeBlake2sTranscript<W> {
    fn write_commitment(&mut self, hash: &Output<Blake2s>) -> Result<(), Error> {
        self.stream
            .write_all(hash)
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        Ok(())
    }
}






