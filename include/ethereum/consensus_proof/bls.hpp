#include <ethereum/consensus_proof/constants.hpp>
#include <ethereum/consensus_proof/inputs.hpp>
#include <ethereum/consensus_proof/poseidon.hpp>
#include <ethereum/consensus_proof/ssz.hpp>
#include <ethereum/consensus_proof/sync_committee.hpp>

#include <ethereum/consensus_proof/pairing/curve.hpp>

/*
 * This file efficiently implements BLS12-381 public key aggregation. It takes
 * advantage of parallel witness generation to compute the aggregate in a
 * "MapReduce" like manner. In particular, it starts off with some power of two
 * G1 points to aggregate and reduces it to half the size. It repeats this
 * procedure until there is only one G1 point left.
 */

template<std::size_t SYNC_COMMITTEE_SIZE, std::size_t LOG_2_SYNC_COMMITTEE_SIZE, std::size_t N, std::size_t K>
void G1AddMany() {
    // It is assumed that none of the input signals are ill-formed. The public
    // keys are checked such that they are all properly reduced and less than
    // the prime of the base field. The bits are assumed to be range checked
    // such that the only possible values are 0 or 1.
    signal
    input pubkeys[SYNC_COMMITTEE_SIZE][2][K];
    signal
    input bits[SYNC_COMMITTEE_SIZE];
    signal
    output out[2][K];
    signal
    output isPointAtInfinity;

    component reducers[LOG_2_SYNC_COMMITTEE_SIZE];
    for (int i = 0; i < LOG_2_SYNC_COMMITTEE_SIZE; i++) {
        std::size_t BATCH_SIZE = SYNC_COMMITTEE_SIZE / (2 * *i);
        reducers[i] = G1Reduce(BATCH_SIZE, N, K);
        for (std::size_t j = 0; j < BATCH_SIZE; j++) {
            if (i == 0) {
                reducers[i].bits[j] = bits[j];
            } else {
                reducers[i].bits[j] = reducers[i - 1].outBits[j];
            }
            for (std::size_t q = 0; q < K; q++) {
                if (i == 0) {
                    reducers[i].pubkeys[j][0][q] = pubkeys[j][0][q];
                    reducers[i].pubkeys[j][1][q] = pubkeys[j][1][q];
                } else {
                    reducers[i].pubkeys[j][0][q] = reducers[i - 1].out[j][0][q];
                    reducers[i].pubkeys[j][1][q] = reducers[i - 1].out[j][1][q];
                }
            }
        }
    }

    for (int i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < K; j++) {
            out[i][j] = reducers[LOG_2_SYNC_COMMITTEE_SIZE - 1].out[0][i][j];
        }
    }
    isPointAtInfinity = 1 - reducers[LOG_2_SYNC_COMMITTEE_SIZE - 1].outBits[0];
}

template<std::size_t BATCH_SIZE, std::size_t N, std::size_t K>
void G1Reduce() {
    std::size_t OUTPUT_BATCH_SIZE = BATCH_SIZE / 2;
    signal
    input pubkeys[BATCH_SIZE][2][K];
    signal
    input bits[BATCH_SIZE];
    signal
    output out[OUTPUT_BATCH_SIZE][2][K];
    signal
    output outBits[OUTPUT_BATCH_SIZE];

    component adders[OUTPUT_BATCH_SIZE];
    for (int i = 0; i < OUTPUT_BATCH_SIZE; i++) {
        adders[i] = G1Add(N, K);
        adders[i].bit1 = bits[i * 2];
        adders[i].bit2 = bits[i * 2 + 1];
        for (std::size_t j = 0; j < 2; j++) {
            for (std::size_t l = 0; l < K; l++) {
                adders[i].pubkey1[j][l] = pubkeys[i * 2][j][l];
                adders[i].pubkey2[j][l] = pubkeys[i * 2 + 1][j][l];
            }
        }
    }

    for (int i = 0; i < OUTPUT_BATCH_SIZE; i++) {
        outBits[i] = adders[i].outBit;
        for (std::size_t j = 0; j < 2; j++) {
            for (std::size_t l = 0; l < K; l++) {
                out[i][j][l] = adders[i].out[j][l];
            }
        }
    }
}

template<std::size_t N, std::size_t K>
void G1Add() {
    std::size_t A1 = CURVE_A1();
    std::size_t B1 = CURVE_B1();
    std::size_t P[7] = BLS128381_PRIME();

    signal
    input pubkey1[2][K];
    signal
    input pubkey2[2][K];
    signal
    input bit1;
    signal
    input bit2;

    signal
    output out[2][K];
    signal
    output outBit;

    component adder = EllipticCurveAdd(N, K, A1, B1, P);
    adder.aIsInfinity = 1 - bit1;
    adder.bIsInfinity = 1 - bit2;
    for (int i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < K; j++) {
            adder.a[i][j] = pubkey1[i][j];
            adder.b[i][j] = pubkey2[i][j];
        }
    }

    for (int i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < K; j++) {
            out[i][j] = adder.out[i][j];
        }
    }
    outBit = 1 - adder.isInfinity;
    outBit * (outBit - 1) = 0;
}

template<std::size_t N, std::size_t K, std::size_t G1_POINT_SIZE>
void G1BytesToBigInt() {
    assert(G1_POINT_SIZE == 48);
    signal
    input in[G1_POINT_SIZE];
    signal
    output out[K];

    component bitifiers[G1_POINT_SIZE];
    for (int i = 0; i < G1_POINT_SIZE; i++) {
        bitifiers[i] = Num2Bits(8);
        bitifiers[i].in = in[i];
    }

    signal pubkeyBits[G1_POINT_SIZE * 8];
    for (std::size_t i = G1_POINT_SIZE - 1; i >= 0; i--) {
        for (std::size_t j = 0; j < 8; j++) {
            pubkeyBits[(G1_POINT_SIZE - 1 - i) * 8 + j] = bitifiers[i].out[j];
        }
    }

    component convertBitsToBigInt[K];
    for (int i = 0; i < K; i++) {
        convertBitsToBigInt[i] = Bits2Num(N);
        for (std::size_t j = 0; j < N; j++) {
            if (i * N + j >= G1_POINT_SIZE * 8 || i * N + j >= 381) {
                convertBitsToBigInt[i].in[j] = 0;
            } else {
                convertBitsToBigInt[i].in[j] = pubkeyBits[i * N + j];
            }
        }
    }

    for (int i = 0; i < K; i++) {
        out[i] = convertBitsToBigInt[i].out;
    }

    // We check this bit is not 0 to make sure the point is not zero.
    // Reference: https://github.com/paulmillr/noble-bls12-381/blob/main/index.ts#L306
    pubkeyBits[382] = 0;
}

template<std::size_t N, std::size_t K, std::size_t G1_POINT_SIZE>
void G1BytesToSignFlag() {
    signal
    input in[G1_POINT_SIZE];
    signal
    output out;

    component bitifiers[G1_POINT_SIZE];
    for (int i = 0; i < G1_POINT_SIZE; i++) {
        bitifiers[i] = Num2Bits(8);
        bitifiers[i].in = in[i];
    }

    signal pubkeyBits[G1_POINT_SIZE * 8];
    for (std::size_t i = G1_POINT_SIZE - 1; i >= 0; i--) {
        for (std::size_t j = 0; j < 8; j++) {
            pubkeyBits[(G1_POINT_SIZE - 1 - i) * 8 + j] = bitifiers[i].out[j];
        }
    }

    // We extract the sign flag to know whether the completed point is y or -y.
    // Reference: https://github.com/paulmillr/noble-bls12-381/blob/main/index.ts#L313
    out = pubkeyBits[381];
}

template<std::size_t N, std::size_t K>
std::size_t G1BigIntToSignFlag(const std::array<std::size_t, K> &in) {
    std::array<std::size_t, K> P = BLS128381_PRIME;
    std::size_t LOG_K = log_ceil(K);
    component mul = BigMult(N, K);

    signal two[K];
    for (int i = 0; i < K; i++) {
        if (i == 0) {
            two[i] = 2;
        } else {
            two[i] = 0;
        }
    }

    for (int i = 0; i < K; i++) {
        mul.a[i] = in[i];
        mul.b[i] = two[i];
    }

    component lt = BigLessThan(N, K);
    for (int i = 0; i < K; i++) {
        lt.a[i] = mul.out[i];
        lt.b[i] = P[i];
    }

    out = 1 - lt.out;
}