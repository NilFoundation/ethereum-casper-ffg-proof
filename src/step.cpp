#include <array>

#include <ethereum/sync_committee/constants.hpp>
#include <ethereum/sync_committee/inputs.hpp>
#include <ethereum/sync_committee/bls.hpp>
#include <ethereum/sync_committee/poseidon.hpp>
#include <ethereum/sync_committee/ssz.hpp>
#include <ethereum/sync_committee/sync_committee.hpp>

/*
 * Reduces the gas cost of processing a light client update by offloading the
 * verification of the aggregated BLS signature by the sync committee and
 * various merkle proofs (e.g., finality) into a zkSNARK which can be verified
 * on-chain for ~200K gas.
 *
 * @input  attested{HeaderRoot,Slot,ProposerIndex,ParentRoot,StateRoot,BodyRoot}
                                  The header attested to by the sync committee
 and all associated fields.
 * @input finalized{HeaderRoot,Slot,ProposerIndex,ParentRoot,StateRoot,BodyRoot}
                                  The finalized header committed to inside the
 attestedHeader.
 * @input  pubkeysX               X-coordinate of the public keys of the sync
 committee in bigint form.
 * @input  pubkeysY               Y-coordinate of the public keys of the sync
 committee in bigint form.
 * @input  aggregationBits        Bitmap indicating which validators have signed
 * @input  signature              An aggregated signature over signingRoot
 * @input  domain                 sha256(forkVersion, genesisValidatorsRoot)
 * @input  signingRoot            sha256(attestedHeaderRoot, domain)
 * @input  participation          sum(aggregationBits)
 * @input  syncCommitteePoseidon  A commitment to the sync committee pubkeys from rotate.
 * @input  finalityBranch         A Merkle proof for finalizedHeader
 * @input  executionStateRoot     The eth1 state root inside finalizedHeader
 * @input  executionStateBranch   A Merkle proof for executionStateRoot
 * @input  publicInputsRoot       A commitment to all "public inputs"
 */
[[circuit]] void Step(const std::array<std::size_t, 32> &attestedHeaderRoot,
          const std::array<std::size_t, 32> &attestedSlot,
          const std::array<std::size_t, 32> &attestedProposerIndex,
          const std::array<std::size_t, 32> &attestedParentRoot,
          const std::array<std::size_t, 32> &attestedStateRoot,
          const std::array<std::size_t, 32> &attestedBodyRoot,

          const std::array<std::size_t, 32> &finalizedHeaderRoot,
          const std::array<std::size_t, 32> &finalizedSlot,
          const std::array<std::size_t, 32> &finalizedProposerIndex,
          const std::array<std::size_t, 32> &finalizedParentRoot,
          const std::array<std::size_t, 32> &finalizedStateRoot,
          const std::array<std::size_t, 32> &finalizedBodyRoot) {

    std::size_t N = NUM_BITS_PER_REGISTER();
    std::size_t K = NUM_REGISTERS();
    std::size_t SYNC_COMMITTEE_SIZE = SYNC_COMMITTEE_SIZE();
    std::size_t LOG_2_SYNC_COMMITTEE_SIZE = LOG2_SYNC_COMMITTEE_SIZE();
    std::size_t FINALIZED_HEADER_DEPTH = FINALIZED_HEADER_DEPTH();
    std::size_t FINALIZED_HEADER_INDEX = FINALIZED_HEADER_INDEX();
    std::size_t EXECUTION_STATE_ROOT_DEPTH = EXECUTION_STATE_ROOT_DEPTH();
    std::size_t EXECUTION_STATE_ROOT_INDEX = EXECUTION_STATE_ROOT_INDEX();
    std::size_t TRUNCATED_SHA256_SIZE = TRUNCATED_SHA256_SIZE();

    /* Sync Committee Protocol */
    signal input pubkeysX[SYNC_COMMITTEE_SIZE][K];
    signal input pubkeysY[SYNC_COMMITTEE_SIZE][K];
    signal input aggregationBits[SYNC_COMMITTEE_SIZE];
    signal input signature[2][2][K];
    signal input domain[32];
    signal input signingRoot[32];
    signal input participation;
    signal input syncCommitteePoseidon;

    /* Finality Proof */
    signal input finalityBranch[FINALIZED_HEADER_DEPTH][32];

    /* Execution State Proof */
    signal input executionStateRoot[32];
    signal input executionStateBranch[EXECUTION_STATE_ROOT_DEPTH][32];

    /* Commitment to Public Inputs */
    signal input publicInputsRoot;

    /* REDUCE CALLDATA COSTS VIA THE PUBLIC INPUTS ROOT */
    component commitToPublicInputs = CommitToPublicInputsForStep(TRUNCATED_SHA256_SIZE);
    for (int i = 0; i < 32; i++) {
        commitToPublicInputs.attestedSlot[i] <= = attestedSlot[i];
        commitToPublicInputs.finalizedSlot[i] <= = finalizedSlot[i];
        commitToPublicInputs.finalizedHeaderRoot[i] <= = finalizedHeaderRoot[i];
        commitToPublicInputs.executionStateRoot[i] <= = executionStateRoot[i];
    }
    commitToPublicInputs.participation <= = participation;
    commitToPublicInputs.syncCommitteePoseidon <= = syncCommitteePoseidon;

    component bitifyPublicInputsRoot = Num2Bits(TRUNCATED_SHA256_SIZE);
    bitifyPublicInputsRoot.in <= = publicInputsRoot;
    for (int i = 0; i < TRUNCATED_SHA256_SIZE; i++) {
        bitifyPublicInputsRoot.out[i] = commitToPublicInputs.out[i];
    }

    /* VALIDATE BEACON CHAIN DATA AGAINST SIGNING ROOT */
    component sszAttestedHeader = SSZPhase0BeaconBlockHeader();
    component sszFinalizedHeader = SSZPhase0BeaconBlockHeader();
    component sszSigningRoot = SSZPhase0SigningRoot();
    for (int i = 0; i < 32; i++) {
        sszAttestedHeader.slot[i] <= = attestedSlot[i];
        sszAttestedHeader.proposerIndex[i] <= = attestedProposerIndex[i];
        sszAttestedHeader.parentRoot[i] <= = attestedParentRoot[i];
        sszAttestedHeader.stateRoot[i] <= = attestedStateRoot[i];
        sszAttestedHeader.bodyRoot[i] <= = attestedBodyRoot[i];

        sszFinalizedHeader.slot[i] <= = finalizedSlot[i];
        sszFinalizedHeader.proposerIndex[i] <= = finalizedProposerIndex[i];
        sszFinalizedHeader.parentRoot[i] <= = finalizedParentRoot[i];
        sszFinalizedHeader.stateRoot[i] <= = finalizedStateRoot[i];
        sszFinalizedHeader.bodyRoot[i] <= = finalizedBodyRoot[i];

        sszSigningRoot.headerRoot[i] <= = attestedHeaderRoot[i];
        sszSigningRoot.domain[i] <= = domain[i];
    }
    for (int i = 0; i < 32; i++) {
        sszAttestedHeader.out[i] = attestedHeaderRoot[i];
        sszFinalizedHeader.out[i] = finalizedHeaderRoot[i];
        sszSigningRoot.out[i] = signingRoot[i];
    }

    /* VERIFY SYNC COMMITTEE SIGNATURE AND COMPUTE PARTICIPATION */
    component verifySignature = VerifySyncCommitteeSignature(SYNC_COMMITTEE_SIZE, LOG_2_SYNC_COMMITTEE_SIZE, N, K);
    for (int i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        verifySignature.aggregationBits[i] <= = aggregationBits[i];
        for (std::size_t j = 0; j < K; j++) {
            verifySignature.pubkeys[i][0][j] <= = pubkeysX[i][j];
            verifySignature.pubkeys[i][1][j] <= = pubkeysY[i][j];
        }
    }
    for (int i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < 2; j++) {
            for (std::size_t l = 0; l < K; l++) {
                verifySignature.signature[i][j][l] <= = signature[i][j][l];
            }
        }
    }
    for (int i = 0; i < 32; i++) {
        verifySignature.signingRoot[i] <= = signingRoot[i];
    }
    verifySignature.syncCommitteeRoot <= = syncCommitteePoseidon;
    verifySignature.participation = participation;

    /* VERIFY FINALITY PROOF */
    component verifyFinality = SSZRestoreMerkleRoot(FINALIZED_HEADER_DEPTH, FINALIZED_HEADER_INDEX);
    for (int i = 0; i < 32; i++) {
        verifyFinality.leaf[i] <= = finalizedHeaderRoot[i];
        for (std::size_t j = 0; j < FINALIZED_HEADER_DEPTH; j++) {
            verifyFinality.branch[j][i] <= = finalityBranch[j][i];
        }
    }
    for (int i = 0; i < 32; i++) {
        verifyFinality.out[i] = attestedStateRoot[i];
    }

    /* VERIFY EXECUTION STATE PROOF */
    component verifyExecutionState = SSZRestoreMerkleRoot(EXECUTION_STATE_ROOT_DEPTH, EXECUTION_STATE_ROOT_INDEX);
    for (int i = 0; i < 32; i++) {
        verifyExecutionState.leaf[i] <= = executionStateRoot[i];
        for (std::size_t j = 0; j < EXECUTION_STATE_ROOT_DEPTH; j++) {
            verifyExecutionState.branch[j][i] <= = executionStateBranch[j][i];
        }
    }
    for (int i = 0; i < 32; i++) {
        verifyExecutionState.out[i] = finalizedBodyRoot[i];
    }
}

component main {public[publicInputsRoot]} = Step();