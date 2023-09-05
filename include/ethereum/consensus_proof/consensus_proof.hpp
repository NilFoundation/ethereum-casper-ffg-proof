#include <array>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate_verify.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate_verify_single_msg.hpp>

#include <nil/crypto3/pubkey/bls.hpp>

#include <ethereum/consensus_proof/hash_to_field.hpp>
#include <ethereum/consensus_proof/pairing/bls_signature.hpp>

/*
 * Implements all logic regarding verifying the sync committee validator set
 * and signature verification. This template is quite expensive and takes
 * over 20M constraints (which dominates the cost of Step).
 */

template<std::size_t SYNC_COMMITTEE_SIZE, std::size_t LOG_2_SYNC_COMMITTEE_SIZE, std::size_t N, std::size_t K>
std::size_t VerifySyncCommitteeSignature(
        const std::array<std::array<std::array<std::size_t, SYNC_COMMITTEE_SIZE>, 2>, K> &pubkeys,
        const std::array<std::size_t, SYNC_COMMITTEE_SIZE> &aggregation_bits,
        const
        std::array<std::array<typename nil::crypto3::pubkey::public_key<nil::crypto3::pubkey::bls<381>>::signature_type, 2>, 2> &signature,
        const std::array<std::size_t, 32> &signingRoot,
        std::size_t syncCommitteeRoot) {

    /* RANGE CHECK AGGREGATION BITS */
    for (int i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        aggregation_bits[i] * (aggregation_bits[i] - 1) = 0;
    }

    /* HASH SIGNING ROOT TO FIELD */
    component hashToField = HashToField(32);
    for (int i = 0; i < 32; i++) {
        hashToField.msg[i] = signingRoot[i];
    }

    /* VALIDATE PUBKEYS AGAINST SYNC COMMITTEE ROOT */
    component computeSyncCommitteeRoot = PoseidonG1Array(SYNC_COMMITTEE_SIZE, N, K);
    for (int i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        for (std::size_t j = 0; j < K; j++) {
            computeSyncCommitteeRoot.pubkeys[i][0][j] = pubkeys[i][0][j];
            computeSyncCommitteeRoot.pubkeys[i][1][j] = pubkeys[i][1][j];
        }
    }
    syncCommitteeRoot = computeSyncCommitteeRoot.out;

    /* COMPUTE AGGREGATE PUBKEY BASED ON AGGREGATION BITS */
    component getAggregatePublicKey = G1AddMany(SYNC_COMMITTEE_SIZE, LOG_2_SYNC_COMMITTEE_SIZE, N, K);
    for (int i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        getAggregatePublicKey.bits[i] = aggregation_bits[i];
        for (std::size_t j = 0; j < 2; j++) {
            for (std::size_t l = 0; l < K; l++) {
                getAggregatePublicKey.pubkeys[i][j][l] = pubkeys[i][j][l];
            }
        }
    }
    getAggregatePublicKey.isPointAtInfinity = 0;

    /* VERIFY BLS SIGNATURE */
    component verifySignature = CoreVerifyPubkeyG1(N, K);
    for (int i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < K; j++) {
            verifySignature.pubkey[i][j] = getAggregatePublicKey.out[i][j];
            verifySignature.signature[0][i][j] = signature[0][i][j];
            verifySignature.signature[1][i][j] = signature[1][i][j];
            verifySignature.hash[0][i][j] = hashToField.out[0][i][j];
            verifySignature.hash[1][i][j] = hashToField.out[1][i][j];
        }
    }

    /* COMPUTE SYNC COMMITTEE PARTICIPATION */
    std::size_t computedParticipation = 0;
    for (int i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        computedParticipation += aggregation_bits[i];
    }
    participation = computedParticipation;
    component zeroCheck = IsZero();
    zeroCheck.in = computedParticipation;
    zeroCheck.out = 0;
}