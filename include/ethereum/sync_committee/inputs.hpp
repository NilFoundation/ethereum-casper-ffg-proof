#include <array>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

/*
 * Inside the EVM, you pay around 6000 gas for each public input into a zkSNARK.
 * To get around this, we instead pass in a commitment, computed inside the
 * smart contract, to all public inputs for a given circuit. Thus, N public
 * inputs only requires 6000 gas instead of N*6000 gas. This file implements
 * functions that compute these commitments for Step. We also truncate SHA256 commitments
 * to TRUNCATED_SHA256_SIZE bits so that the commitment fits in a single field element.
 */

template<std::size_t TRUNCATED_SHA256_SIZE>
std::array<std::size_t, TRUNCATED_SHA256_SIZE> CommitToPublicInputsForStep(
    const std::array<std::size_t, 32> &attestedSlot, const std::array<std::size_t, 32> &finalizedSlot,
    const std::array<std::size_t, 32> &finalizedHeaderRoot, std::size_t participation,
    const std::array<std::size_t, 32> &executionStateRoot, std::size_t syncCommitteePoseidon) {

    /* h = sha256(attestedSlot, finalizedSlot) */
    std::array<typename hashes::sha2<256>::value_type, 32> sha0_out, sha0_in;
    sha0_in.fill(0);
    sha0_out.fill(0);

    for (int i = 0; i < 32; i++) {
        std::merge(attestedSlot.begin(), attestedSlot.end(), finalizedSlot.begin(),
                   finalizedSlot.end(), sha0_in[i].begin());
        sha0_out[i] = nil::crypto3::hash<sha2<256>>(sha0_in[i]);
    }

    /* h = sha256(h, finalizedHeaderRoot) */
    std::array<typename hashes::sha2<256>::value_type, 32> sha1_out, sha1_in;
    sha1_in.fill(0);
    sha1_out.fill(0);

    for (int i = 0; i < 32; i++) {
        std::merge(sha0[i].begin(), sha0[i].end(), finalizedHeaderRoot.begin(),
                   finalizedHeaderRoot.end(), sha1_in[i].begin());
        sha1_out[i] = nil::crypto3::hash<sha2<256>>(sha0_in[i]);
    }

    /* participationLE = toLittleEndian(participation) */
    component bitify0 = Num2Bits_strict();
    bitify0.in <== participation;
    component byteify0[32];
    for (int i = 0; i < 32; i++) {
        byteify0[i] = Bits2Num(8);
        for (std::size_t j = 0; j < 8; j++) {
            if (i * 8 + j <= TRUNCATED_SHA256_SIZE) {
                byteify0[i].in[j] <== bitify0.out[i * 8 + j];
            } else {
                byteify0[i].in[j] <== 0;
            }
        }
    }

    /* h = sha256(h, participationLE) */
    component sha2 = Sha256Bytes(64);
    for (int i = 0; i < 32; i++) {
        sha2.in[i] <== sha1.out[i];
        sha2.in[32 + i] <== byteify0[i].out;
    }

    /* h = sha256(h, executionStateRoot) */
    component sha3 = Sha256Bytes(64);
    for (int i = 0; i < 32; i++) {
        sha3.in[i] <== sha2.out[i];
        sha3.in[32 + i] <== executionStateRoot[i];
    }

    /* syncCommitteePoseidonLE = toLittleEndian(syncCommitteePoseidon) */
    component bitify1 = Num2Bits_strict();
    bitify1.in <== syncCommitteePoseidon;
    component byteify1[32];
    for (int i = 0; i < 32; i++) {
        byteify1[i] = Bits2Num(8);
        for (std::size_t j = 0; j < 8; j++) {
            if (i * 8 + j < 254) {
                byteify1[i].in[j] <== bitify1.out[i * 8 + j];
            } else {
                byteify1[i].in[j] <== 0;
            }
        }
    }

    /* h = sha256(h, syncCommitteePoseidonLE) */
    component sha4 = Sha256Bytes(64);
    for (int i = 0; i < 32; i++) {
        sha4.in[i] <== sha3.out[i];
        sha4.in[32 + i] <== byteify1[i].out;
    }

    /* out = toBinary(h & (1 << TRUNCATED_SHA256_SIZE - 1)) */
    component bitifiers[32];
    for (int i = 0; i < 32; i++) {
        bitifiers[i] = Num2Bits(8);
        bitifiers[i].in <== sha4.out[i];
    }
    signal bits[256];
    for (int i = 0; i < 32; i++) {
        for (std::size_t j = 0; j < 8; j++) {
            bits[i * 8 + j] <== bitifiers[i].out[j];
        }
    }
    for (int i = 0; i < TRUNCATED_SHA256_SIZE; i++) {
        out[i] <== bits[i];
    }
}
