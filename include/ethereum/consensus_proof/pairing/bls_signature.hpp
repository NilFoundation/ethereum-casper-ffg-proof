#include <ethereum/consensus_proof/pairing/final_exp.hpp>
#include <ethereum/consensus_proof/pairing/pairing.hpp>
#include <ethereum/consensus_proof/pairing/bls12_381_func.hpp>
#include <ethereum/consensus_proof/pairing/bls12_381_hash_to_G2.hpp>

// Input: pubkey in G_1
//        signature, H(m) in G_2
// Output: out = 1 if valid signature, else = 0
// Verifies that e(g1, signature) = e(pubkey, H(m)) by checking e(g1, signature)*e(pubkey, -H(m)) === 1 where e(,) is optimal Ate pairing
template<std::size_t n, std::size_t k>
std::size_t CoreVerifyPubkeyG1NoCheck(const std::array<std::array<std::size_t, 2>, k> &pubkey,
                                      const std::array<std::array<std::array<std::size_t, 2>, 2>, k> &signature,
                                      const std::array<std::array<std::array<std::size_t, 2>, 2>, k> &Hm) {
    std::size_t out;

    std::size_t q[50] = get_BLS12_381_prime(n, k);
    std::size_t x = BLS12381_PARAMETER;
    std::size_t g1[2][50] = get_generator_G1(n, k);

    signal neg_s[2][2][k];
    component neg[2];
    for (std::size_t j = 0; j < 2; j++) {
        neg[j] = FpNegate(n, k, q);
        for (std::size_t idx = 0; idx < k; idx++) {
            neg[j].in[idx] = signature[1][j][idx];
        }
        for (std::size_t idx = 0; idx < k; idx++) {
            neg_s[0][j][idx] = signature[0][j][idx];
            neg_s[1][j][idx] = neg[j].out[idx];
        }
    }

    component miller = MillerLoopFp2Two(n, k,[4, 4], x, q);
    for (std::size_t i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < 2; j++) {
            for (std::size_t idx = 0; idx < k; idx++) {
                miller.P[0][i][j][idx] = neg_s[i][j][idx];
                miller.P[1][i][j][idx] = Hm[i][j][idx];
            }
        }
    }
    for (std::size_t i = 0; i < 2; i++) {
        for (std::size_t idx = 0; idx < k; idx++) {
            miller.Q[0][i][idx] = g1[i][idx];
            miller.Q[1][i][idx] = pubkey[i][idx];
        }
    }

    component finalexp = FinalExponentiate(n, k, q);
    for (std::size_t i = 0; i < 6; i++) {
        for (std::size_t j = 0; j < 2; j++) {
            for (std::size_t idx = 0; idx < k; idx++) {
                finalexp.in[i][j][idx] = miller.out[i][j][idx];
            }
        }
    }

    component is_valid[6][2][k];
    std::size_t total = 12 * k;
    for (std::size_t i = 0; i < 6; i++)
        for (std::size_t j = 0; j < 2; j++)
            for (std::size_t idx = 0; idx < k; idx++) {
                is_valid[i][j][idx] = IsZero();
                if (i == 0 && j == 0 && idx == 0)
                    is_valid[i][j][idx].in = finalexp.out[i][j][idx] - 1;
                else
                    is_valid[i][j][idx].in = finalexp.out[i][j][idx];
                total -= is_valid[i][j][idx].out;
            }
    component valid = IsZero();
    valid.in = total;
    out = valid.out;
}

// Inputs:
//   - pubkey as element of E(Fq)
//   - hash represents two field elements in Fp2, in practice hash = hash_to_field(msg,2).
//   - signature, as element of E2(Fq2) 
// Assume signature is not point at infinity 
template<std::size_t n, std::size_t k>
void CoreVerifyPubkeyG1() {
    signal
    input pubkey[2][k];
    signal
    input signature[2][2][k];
    signal
    input hash[2][2][k];

    std::size_t q[50] = get_BLS12_381_prime(n, k);

    component lt[10];
    // check all len k input arrays are correctly formatted bigints < q (BigLessThan calls Num2Bits)
    for (std::size_t i = 0; i < 10; i++) {
        lt[i] = BigLessThan(n, k);
        for (std::size_t idx = 0; idx < k; idx++)
            lt[i].b[idx] = q[idx];
    }
    for (std::size_t idx = 0; idx < k; idx++) {
        lt[0].a[idx] = pubkey[0][idx];
        lt[1].a[idx] = pubkey[1][idx];
        lt[2].a[idx] = signature[0][0][idx];
        lt[3].a[idx] = signature[0][1][idx];
        lt[4].a[idx] = signature[1][0][idx];
        lt[5].a[idx] = signature[1][1][idx];
        lt[6].a[idx] = hash[0][0][idx];
        lt[7].a[idx] = hash[0][1][idx];
        lt[8].a[idx] = hash[1][0][idx];
        lt[9].a[idx] = hash[1][1][idx];
    }

    for (std::size_t idx = 0; idx < 10; idx++) {
        lt[idx].out == = 1;
    }

    // check all registers are in [0, 2^n)
    component check[5];
    for (std::size_t i = 0; i < 5; i++)
        check[i] = RangeCheck2D(n, k);
    for (std::size_t i = 0; i < 2; i++)
        for (std::size_t idx = 0; idx < k; idx++) {
            check[0].in[i][idx] = pubkey[i][idx];
            check[1].in[i][idx] = signature[0][i][idx];
            check[2].in[i][idx] = signature[1][i][idx];
            check[3].in[i][idx] = hash[0][i][idx];
            check[4].in[i][idx] = hash[1][i][idx];
        }

    component pubkey_valid = SubgroupCheckG1(n, k);
    for (std::size_t i = 0; i < 2; i++)
        for (std::size_t idx = 0; idx < k; idx++)
            pubkey_valid.in[i][idx] = pubkey[i][idx];

    component signature_valid = SubgroupCheckG2(n, k);
    for (std::size_t i = 0; i < 2; i++)
        for (std::size_t j = 0; j < 2; j++)
            for (std::size_t idx = 0; idx < k; idx++)
                signature_valid.in[i][j][idx] = signature[i][j][idx];

    component Hm = MapToG2(n, k);
    for (std::size_t i = 0; i < 2; i++)
        for (std::size_t j = 0; j < 2; j++)
            for (std::size_t idx = 0; idx < k; idx++)
                Hm.in[i][j][idx] = hash[i][j][idx];

    Hm.isInfinity == = 0;

    component verify = CoreVerifyPubkeyG1NoCheck(n, k);

    for (std::size_t i = 0; i < 2; i++)
        for (std::size_t idx = 0; idx < k; idx++)
            verify.pubkey[i][idx] = pubkey[i][idx];
    for (std::size_t i = 0; i < 2; i++)
        for (std::size_t j = 0; j < 2; j++)
            for (std::size_t idx = 0; idx < k; idx++) {
                verify.signature[i][j][idx] = signature[i][j][idx];
                verify.Hm[i][j][idx] = Hm.out[i][j][idx];
            }

    verify.out == = 1;
}
