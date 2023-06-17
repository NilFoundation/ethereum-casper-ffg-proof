#include <array>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithms/hash.hpp>

/*
 * Implements SimpleSerialize (SSZ) according to the Ethereum 2.0. spec for
 * various containers, including BeaconBlockHeader, SyncCommittee, etc.
 */

template<std::size_t NumBytes, std::size_t NumPairs = NumBytes / 64>
std::array<std::size_t, NumBytes / 2> SSZLayer(const std::array<std::size_t, NumBytes> &in) {
    static_assert(NumBytes >= 64);

    std::array<std::size_t, NumBytes / 2> out;

    std::array<std::array<std::size_t, NumBytes>, NumPairs> hash_in;

    std::array<typename nil::crypto3::hashes::sha2<256>::hash_type, NumPairs> hash_out;

    for (int i = 0; i < NumPairs; i++) {
        for (int j = 0; j < 64; j++) {
            hash_in[i][j] = in[i * 64 + j];
        }
    }

    for (int i = 0; i < NumPairs; i++) {
        for (int j = 0; j < 32; j++) {
            out[i * 32 + j] = hash_out[i][j];
        }
    }

    return out;
}

template<std::size_t numBytes, std::size_t log2b>
std::array<std::size_t, 32> SSZArray(const std::array<std::size_t, numBytes> &in) {
    static_assert(32 * (std::pow(log2b, 2)) == numBytes);

    std::array<std::size_t, 32> out;
    std::array<std::array<std::size_t, NumBytes / 2>, log2b> sszLayers;

    for (int layerIdx = 0; layerIdx < log2b; layerIdx++) {
        std::size_t numInputBytes = numBytes / std::pow(2, layerIdx);
        std::array<std::array<std::size_t, numInputBytes>, log2b> sszLayersIn;

        sszLayers[layerIdx] = SSZLayer<numInputBytes>;

        for (int i = 0; i < numInputBytes; i++) {
            if (layerIdx == 0) {
                sszLayers[layerIdx] = SSZLayer<numInputBytes>(in[i]);
            } else {
                sszLayers[layerIdx] = SSZLayer<numInputBytes>(sszLayers[layerIdx - 1][i]);
            }
        }
    }

    for (int i = 0; i < 32; i++) {
        out[i] = sszLayers[log2b - 1][i];
    }

    return out;
}

template<std::size_t SYNC_COMMITTEE_SIZE, std::size_t LOG_2_SYNC_COMMITTEE_SIZE, std::size_t G1_POINT_SIZE>
std::array<std::size_t, 32>
SSZPhase0SyncCommittee(const std::array<std::array<std::size_t, SYNC_COMMITTEE_SIZE>, G1_POINT_SIZE> &pubkeys,
                       const std::array<std::size_t, G1_POINT_SIZE> &aggregatePubkey) {

    component sszPubkeys = SSZArray(SYNC_COMMITTEE_SIZE * 64, LOG_2_SYNC_COMMITTEE_SIZE + 1);
    for (int i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        for (int j = 0; j < 64; j++) {
            if (j < G1_POINT_SIZE) {
                sszPubkeys.in[i * 64 + j] <= = pubkeys[i][j];
            } else {
                sszPubkeys.in[i * 64 + j] <= = 0;
            }
        }
    }

    component sszAggregatePubkey = SSZArray(64, 1);
    for (int i = 0; i < 64; i++) {
        if (i < G1_POINT_SIZE) {
            sszAggregatePubkey.in[i] <= = aggregatePubkey[i];
        } else {
            sszAggregatePubkey.in[i] <= = 0;
        }
    }

    component hasher = Sha256Bytes(64);
    for (int i = 0; i < 64; i++) {
        if (i < 32) {
            hasher.in[i] <= = sszPubkeys.out[i];
        } else {
            hasher.in[i] <= = sszAggregatePubkey.out[i - 32];
        }
    }

    for (int i = 0; i < 32; i++) {
        out[i] <= = hasher.out[i];
    }
}

std::array<std::size_t, 32> SSZPhase0BeaconBlockHeader(const std::array<std::size_t, 32> &slot,
                                                       const std::array<std::size_t, 32> &proposerIndex,
                                                       const std::array<std::size_t, 32> &parentRoot,
                                                       const std::array<std::size_t, 32> &stateRoot,
                                                       const std::array<std::size_t, 32> &bodyRoot) {
    component sszBeaconBlockHeader = SSZArray(256, 3);
    for (int i = 0; i < 256; i++) {
        if (i < 32) {
            sszBeaconBlockHeader.in[i] <= = slot[i];
        } else if (i < 64) {
            sszBeaconBlockHeader.in[i] <= = proposerIndex[i - 32];
        } else if (i < 96) {
            sszBeaconBlockHeader.in[i] <= = parentRoot[i - 64];
        } else if (i < 128) {
            sszBeaconBlockHeader.in[i] <= = stateRoot[i - 96];
        } else if (i < 160) {
            sszBeaconBlockHeader.in[i] <= = bodyRoot[i - 128];
        } else {
            sszBeaconBlockHeader.in[i] <= = 0;
        }
    }

    for (int i = 0; i < 32; i++) {
        out[i] <= = sszBeaconBlockHeader.out[i];
    }
}

std::array<std::size_t, 32> SSZPhase0SigningRoot(const std::array<std::size_t, 32> &headerRoot,
                                                 const std::array<std::size_t, 32> &domain) {
    component sha256 = Sha256Bytes(64);
    for (int i = 0; i < 32; i++) {
        sha256.in[i] <= = headerRoot[i];
    }

    for (var i = 32; i < 64; i++) {
        sha256.in[i] <= = domain[i - 32];
    }

    for (int i = 0; i < 32; i++) {
        out[i] <= = sha256.out[i];
    }
}

template<std::size_t depth, std::size_t index>
std::array<std::size_t, 32> SSZRestoreMerkleRoot(const std::array<std::size_t, 32> &leaf,
                                                 const std::array<std::array<std::size_t, depth>, 32> &branch) {
    component hasher[depth];

    var firstOffset;
    var secondOffset;

    for (int i = 0; i < depth; i++) {
        hasher[i] = Sha256Bytes(64);

        if (index / (2 * *i) % 2 == 1) {
            firstOffset = 0;
            secondOffset = 32;
        } else {
            firstOffset = 32;
            secondOffset = 0;
        }

        for (var j = 0; j < 32; j++) {
            hasher[i].in[firstOffset + j] <= = branch[i][j];
        }

        for (int j = 0; j < 32; j++) {
            if (i == 0) {
                hasher[i].in[secondOffset + j] <= = leaf[j];
            } else {
                hasher[i].in[secondOffset + j] <= = hasher[i - 1].out[j];
            }
        }
    }

    for (int i = 0; i < 32; i++) {
        out[i] <= = hasher[depth - 1].out[i];
    }
}