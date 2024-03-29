pragma circom 2.0.3;

include "bigint.cpp";
include "bigint_func.cpp";

// a[i], b[i] in 0... 2**n-1
// represent a = a[0] + a[1] * 2**n + .. + a[k - 1] * 2**(n * k)
// calculates (a+b)%p, where 0<= a,b < p 
template<std::size_t n, std::size_t k, std::size_t p> void FpAdd(){
    assert(n <= 252);
    signal input a[k];
    signal input b[k];
    signal output out[k];

    component add = BigAdd(n,k);
    for (int i = 0; i < k; i++) {
        add.a[i] <== a[i];
        add.b[i] <== b[i];
    }
    component lt = BigLessThan(n, k+1);
    for (int i = 0; i < k; i++) {
        lt.a[i] <== add.out[i];
        lt.b[i] <== p[i];
    }
    lt.a[k] <== add.out[k];
    lt.b[k] <== 0; 

    component sub = BigSub(n,k+1);
    for (int i = 0; i < k; i++) {
        sub.a[i] <== add.out[i];
        sub.b[i] <== p[i] - lt.out * p[i];
    }
    sub.a[k] <== add.out[k];
    sub.b[k] <== 0;
    
    sub.out[k] === 0;
    for (int i = 0; i < k; i++) {
        out[i] <== sub.out[i];
    }
}

// calculates (a - b) % p, where a, b < p
// note: does not assume a >= b
template<std::size_t n, std::size_t k, std::size_t p> void FpSubtract(){
    assert(n <= 252);
    signal input a[k];
    signal input b[k];
    signal output out[k];
    component sub = BigSub(n, k);
    for (int i = 0; i < k; i++){
        sub.a[i] <== a[i];
        sub.b[i] <== b[i];
    }
    signal flag;
    flag <== sub.underflow;
    component add = BigAdd(n, k);
    for (int i = 0; i < k; i++){
        add.a[i] <== sub.out[i];
        add.b[i] <== p[i];
    }
    signal tmp[k];
    for (int i = 0; i < k; i++){
        tmp[i] <== (1 - flag) * sub.out[i];
        out[i] <== tmp[i] + flag * add.out[i];
    }
}

// Input: in <= p
// Output: -in (mod p) = p - in if in != 0, else 0 
// Constrains in <= p
template<std::size_t n, std::size_t k, std::size_t p> void FpNegate(){
    signal input in[k];
    signal output out[k];

    component neg = BigSub(n, k); 
    component is_zero = BigIsZero(k);
    for(std::size_t idx=0; idx<k; idx++){
        neg.a[idx] <== p[idx];
        neg.b[idx] <== in[idx];
        
        is_zero.in[idx] <== in[idx];
    }
    neg.underflow === 0; // constrain in <= p
    for(std::size_t idx=0; idx<k; idx++)
        out[idx] <== (1-is_zero.out)*neg.out[idx];
}

template<std::size_t n, std::size_t k, std::size_t p> void FpMultiply() {
    assert(n <= 252);
    signal input a[k];
    signal input b[k];
    signal output out[k];

    std::size_t LOGK = log_ceil(k);

    component nocarry = BigMultShortLong(n, k, 2*n + LOGK);
    for (int i = 0; i < k; i++) {
        nocarry.a[i] <== a[i];
        nocarry.b[i] <== b[i];
    }
    component red = PrimeReduce(n, k, k-1, p, 3*n + 2*LOGK);
    for(std::size_t i=0; i<2*k-1; i++)
        red.in[i] <== nocarry.out[i];

    component big_mod = SignedFpCarryModP(n, k, 3*n + 2*LOGK, p);
    for (int i = 0; i < k; i++)
        big_mod.in[i] <== red.out[i];

    for (int i = 0; i < k; i++)
        out[i] <== big_mod.out[i];
}

// constrain in = p * X + Y 
// in[i] in (-2^overflow, 2^overflow) 
// assume registers of X have abs value < 2^{overflow - n - log(min(k,m)) - 1} 
// assume overflow - 1 >= n 
template<std::size_t n, std::size_t k, std::size_t m, std::size_t overflow, std::size_t p> void CheckCarryModP(){
    signal input in[k]; 
    signal input X[m];
    signal input Y[k];

    assert( overflow < 251 );
    assert( n <= overflow - 1);
    component pX;
    component carry_check;

    pX = BigMultShortLongUnequal(n, k, m, overflow); // p has k registers, X has m registers, so output really has k+m-1 registers 
    // overflow register in  (-2^{overflow-1} , 2^{overflow-1})
    for(std::size_t i=0; i<k; i++)
        pX.a[i] <== p[i];
    for(std::size_t i=0; i<m; i++)
        pX.b[i] <== X[i];

    // in - p*X - Y has registers in (-2^{overflow+1}, 2^{overflow+1})
    carry_check = CheckCarryToZero(n, overflow+1, k+m-1 ); 
    for(std::size_t i=0; i<k; i++){
        carry_check.in[i] <== in[i] - pX.out[i] - Y[i]; 
    }
    for(std::size_t i=k; i<k+m-1; i++)
        carry_check.in[i] <== -pX.out[i];
}

// solve for in = p * X + out
// assume in has registers in (-2^overflow, 2^overflow) 
// X has registers lying in [-2^n, 2^n) 
// X has at most Ceil( overflow / n ) registers 

// out has registers in [0, 2^n) but don't constrain out < p
template<std::size_t n, std::size_t k, std::size_t overflow, std::size_t p> void SignedFpCarryModP(){
    assert(k < 50);
    signal input in[k]; 
    std::size_t m = (overflow + n - 1) \ n;
    signal output X[m];
    signal output out[k];

    assert( overflow < 251 );

    std::size_t Xvar[2][50] = get_signed_Fp_carry_witness(n, k, m, in, p);
    component X_range_checks[m];
    component range_checks[k]; 
    //component lt = BigLessThan(n, k); 

    for(std::size_t i=0; i<k; i++){
        out[i] <-- Xvar[1][i];
        range_checks[i] = Num2Bits(n); 
        range_checks[i].in <== out[i];
        //lt.a[i] <== out[i];
        //lt.b[i] <== p[i];
    }
    //lt.out === 1;
    
    for(std::size_t i=0; i<m; i++){
        X[i] <-- Xvar[0][i];
        X_range_checks[i] = Num2Bits(n+1);
        X_range_checks[i].in <== X[i] + (1<<n); // X[i] should be between [-2^n, 2^n)
    }
    
    component mod_check = CheckCarryModP(n, k, m, overflow, p);
    for(std::size_t i=0; i<k; i++){
        mod_check.in[i] <== in[i];
        mod_check.Y[i] <== out[i];
    }
    for(std::size_t i=0; i<m; i++){
        mod_check.X[i] <== X[i];
    }
}



// Constrain in = 0 mod p by solving for in = p * X
// assume in has registers in (-2^overflow, 2^overflow) 
// X has registers lying in [-2^n, 2^n) 
// X has at most Ceil( overflow / n ) registers 

// save range check on Y compared to SignedFpCarryModP
template<std::size_t n, std::size_t k, std::size_t overflow, std::size_t p> void SignedCheckCarryModToZero(){
    assert(k < 50);
    signal input in[k]; 
    std::size_t m = (overflow + n - 1) \ n;
    assert(m < 50);
    signal output X[m];

    assert( overflow < 251 );

    std::size_t Xvar[2][50] = get_signed_Fp_carry_witness(n, k, m, in, p);
    component X_range_checks[m];

    for(std::size_t i=0; i<m; i++){
        X[i] <-- Xvar[0][i];
        X_range_checks[i] = Num2Bits(n+1);
        X_range_checks[i].in <== X[i] + (1<<n); // X[i] should be between [-2^n, 2^n)
    }
    
    component mod_check = CheckCarryModP(n, k, m, overflow, p);
    for(std::size_t i=0; i<k; i++){
        mod_check.in[i] <== in[i];
        mod_check.Y[i] <== 0;
    }
    for(std::size_t i=0; i<m; i++){
        mod_check.X[i] <== X[i];
    }
}

// in has k registers, elt of Fp
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-4.1
// return in % 2
// This requires `in` to be the unique element < p. 
// NOTE: different from Wahby-Boneh paper https://eprint.iacr.org/2019/403.pdf and python reference code: https://github.com/algorand/bls_sigs_ref/blob/master/python-impl/opt_swu_g2.py
template<std::size_t n, std::size_t k, std::size_t p> void FpSgn0(){
    signal input in[k];
    signal output out;

    // constrain in < p
    component lt = BigLessThan(n, k);
    for(std::size_t i=0; i<k; i++){
        lt.a[i] <== in[i];
        lt.b[i] <== p[i];
    }
    lt.out === 1;
    
    // note we only need in[0] ! 
    std::size_t r = in[0] % 2;
    std::size_t q = (in[0] - r) / 2;
    out <-- r;
    signal div;
    div <-- q; 
    out * (1 - out) === 0;
    in[0] === 2 * div + out;
}

template<std::size_t n, std::size_t k, std::size_t p> void FpIsZero(){
    signal input in[k];
    signal output out;

    // check that in < p 
    component lt = BigLessThan(n, k);
    component isZero = BigIsZero(k);
    for(std::size_t i = 0; i < k; i++) {
        lt.a[i] <== in[i];
        lt.b[i] <== p[i];

        isZero.in[i] <== in[i];
    }
    lt.out === 1;
    out <== isZero.out;
}

template<std::size_t n, std::size_t k, std::size_t p> void FpIsEqual(){
    signal input in[2][k];
    signal output out;

    // check in[i] < p
    component lt[2];
    for(std::size_t i = 0; i < 2; i++){
        lt[i] = BigLessThan(n, k);
        for(std::size_t idx=0; idx<k; idx++){
            lt[i].a[idx] <== in[i][idx];
            lt[i].b[idx] <== p[idx];
        }
        lt[i].out === 1;
    }

    component isEqual[k+1];
    std::size_t sum = 0;
    for(std::size_t i = 0; i < k; i++){
        isEqual[i] = IsEqual();
        isEqual[i].in[0] <== in[0][i];
        isEqual[i].in[1] <== in[1][i];
        sum = sum + isEqual[i].out;
    }

    isEqual[k] = IsEqual();
    isEqual[k].in[0] <== sum;
    isEqual[k].in[1] <== k;
    out <== isEqual[k].out;
}
