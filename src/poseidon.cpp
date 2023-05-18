#include <array>

/*
 * Helper functions for computing Poseidon commitments to the sync committee's
 * validator public keys.
 */

template<std::size_t LENGTH, std::size_t N, std::size_t K>
std::size_t PoseidonG1Array(const std::array<std::array<std::array<std::size_t, K>, 2>, LENGTH> &pubkeys) {
    component hasher = PoseidonSponge(LENGTH * 2 * K);
    for (var i = 0; i < LENGTH; i++) {
        for (var j = 0; j < K; j++) {
            for (var l = 0; l < 2; l++) {
                hasher.in[(i * K * 2) + (j * 2) + l] <= = pubkeys[i][l][j];
            }
        }
    }
    out <= = hasher.out;
}

template<std::size_t LENGTH>
std::size_t PoseidonSponge(const std::array<std::size_t, LENGTH> &in) {
    static_assert(LENGTH % 16 == 0);

    var POSEIDON_SIZE = 16;
    var NUM_ROUNDS = LENGTH \ POSEIDON_SIZE;

    component hashers[NUM_ROUNDS];
    for (var i = 0; i < NUM_ROUNDS; i++) {
        if (i < NUM_ROUNDS - 1) {
            hashers[i] = PoseidonEx(POSEIDON_SIZE, 1);
        } else {
            hashers[i] = PoseidonEx(POSEIDON_SIZE, 2);
        }
        for (var j = 0; j < POSEIDON_SIZE; j++) {
            hashers[i].inputs[j] <= = in[i * POSEIDON_SIZE + j];
        }

        if (i == 0) {
            hashers[i].initialState <= = 0;
        } else {
            hashers[i].initialState <= = hashers[i - 1].out[0];
        }
    }

    out <= = hashers[NUM_ROUNDS - 1].out[1];
}