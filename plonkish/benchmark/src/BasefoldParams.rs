#[derive(Debug)]
pub struct Ten {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Ten {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 381;
    }

    fn get_rs_basecode() -> bool{
    true
    }
}
#[derive(Debug)]
pub struct Eleven {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Eleven {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 401;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct TwoFiftySixBasecode4 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwoFiftySixBasecode4 {
    fn get_rate() -> usize {
        return 1;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 694;
    }
    fn get_rs_basecode() -> bool{
    true
    }    

}


#[derive(Debug)]
pub struct BasefoldFri {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for BasefoldFri {
    fn get_rate() -> usize {
        return 1;
    }

    fn get_basecode_rounds() -> usize {
        return 0;
    }

    fn get_reps() -> usize {
        return 401;
    }
    fn get_rs_basecode() -> bool{
    false
    }    
}


#[derive(Debug)]
pub struct BasefoldFriR2 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for BasefoldFriR2 {
    fn get_rate() -> usize {
        return 1;
    }

    fn get_basecode_rounds() -> usize {
        return 0;
    }

    fn get_reps() -> usize {
        return 401;
    }
    fn get_rs_basecode() -> bool{
    false
    }    
}

#[derive(Debug)]
pub struct BasefoldFriR4 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for BasefoldFriR4 {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 0;
    }

    fn get_reps() -> usize {
        return 401;
    }
    fn get_rs_basecode() -> bool{
    false
    }    
}
#[derive(Debug)]
pub struct BasefoldFriR8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for BasefoldFriR8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 0;
    }

    fn get_reps() -> usize {
        return 401;
    }
    fn get_rs_basecode() -> bool{
    false
    }    
}

#[derive(Debug)]
pub struct TwoFiftySixBasecode1 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwoFiftySixBasecode1 {
    fn get_rate() -> usize {
        return 1;
    }

    fn get_basecode_rounds() -> usize {
        return 0;
    }

    fn get_reps() -> usize {
        return 1550;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}

#[derive(Debug)]
pub struct Twelve {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Twelve {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 422;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Thirteen {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Thirteen {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 445;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Fourteen {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Fourteen {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 470;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]    
pub struct Fifteen {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Fifteen {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 497;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Sixteen {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Sixteen {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 528;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Seventeen  {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Seventeen {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 561;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Eighteen {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Eighteen {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 599;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Nineteen {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Nineteen {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 641;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Twenty {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Twenty {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 689;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct TwentyOne {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwentyOne {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 744;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct TwentyTwo {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwentyTwo {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 808;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct TwentyThree {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwentyThree {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 882;
    }
    fn get_rs_basecode() -> bool{
    true
    }
}
#[derive(Debug)]
pub struct TwentyFour {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwentyFour {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 971;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct TwentyFive {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwentyFive {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 1077;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct TwentySix {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwentySix {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 1208;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}

#[derive(Debug)]
pub struct Ten8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Ten8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 269;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Eleven8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Eleven8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 280;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Twelve8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Twelve8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 292;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Thirteen8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Thirteen8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 305;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Fourteen8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Fourteen8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 319;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]    
pub struct Fifteen8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Fifteen8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 333;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Sixteen8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Sixteen8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 349;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Seventeen8  {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Seventeen8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 366;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Eighteen8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Eighteen8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 384;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Nineteen8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Nineteen8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 403;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct Twenty8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for Twenty8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 424;
    }
    fn get_rs_basecode() -> bool{
    true
    }
}
#[derive(Debug)]
pub struct TwentyOne8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwentyOne8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 447;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct TwentyTwo8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwentyTwo8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 473;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct TwentyThree8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwentyThree8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 500;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct TwentyFour8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwentyFour8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 531;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct TwentyFive8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwentyFive8 {
    fn get_rate() -> usize {
        return 3;
    }
    fn get_basecode_rounds() -> usize {

        return 1;
    }

    fn get_reps() -> usize {
        return 565;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}
#[derive(Debug)]
pub struct TwentySix8 {}
impl plonkish_backend::pcs::multilinear::BasefoldExtParams for TwentySix8 {
    fn get_rate() -> usize {
        return 3;
    }

    fn get_basecode_rounds() -> usize {
        return 1;
    }

    fn get_reps() -> usize {
        return 603;
    }
    fn get_rs_basecode() -> bool{
    true
    }    
}


