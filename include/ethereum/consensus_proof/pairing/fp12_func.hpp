function find_Fp12_sum(n, k, a, b, p) {
    std::size_t out[6][2][50];
    for(std::size_t i=0; i<6; i++)
        out[i] = find_Fp2_sum(n, k, a[i], b[i], p);
    return out;
}

function find_Fp12_diff(n, k, a, b, p) {
    std::size_t out[6][2][50];
    for(std::size_t i=0; i<6; i++)
        out[i] = find_Fp2_diff(n, k, a[i], b[i], p);
    return out;
}

function find_Fp12_product(n, k, a, b, p) {
    std::size_t l = 6;
    std::size_t a0[l][50];
    std::size_t a1[l][50];
    std::size_t b0[l][50];
    std::size_t b1[l][50];
    std::size_t neg_b0[l][50];
    std::size_t neg_b1[l][50];
    std::size_t out[l][2][50];
    for (int i = 0; i < l; i ++) {
        for ( std::size_t j = 0; j < k; j ++) {
            a0[i][j] = a[i][0][j];
            a1[i][j] = a[i][1][j];
            b0[i][j] = b[i][0][j];
            b1[i][j] = b[i][1][j];
        }
    }
    for ( std::size_t i = 0; i < l; i ++) {
        neg_b0[i] = long_sub(n, k, p, b0[i]);
        neg_b1[i] = long_sub(n, k, p, b1[i]);
    }

    std::size_t real_init[20][50];
    std::size_t imag_init[20][50];
    std::size_t imag_init_neg[20][50];
    // std::size_t real[l][2][50];
    // std::size_t imag[l][2][50];
    // each product will be 2l-1 x 2k
    std::size_t a0b0_var[20][50] = prod2D(n, k, l, a0, b0);
    std::size_t a1b1_neg[20][50] = prod2D(n, k, l, a1, neg_b1);
    std::size_t a0b1_var[20][50] = prod2D(n, k, l, a0, b1);
    std::size_t a1b0_var[20][50] = prod2D(n, k, l, a1, b0);
    std::size_t a0b1_neg[20][50] = prod2D(n, k, l, a0, neg_b1);
    std::size_t a1b0_neg[20][50] = prod2D(n, k, l, a1, neg_b0);
    for (int i = 0; i < 2*l - 1; i ++) { // compute initial rep (deg w = 10)
        real_init[i] = long_add(n, 2*k, a0b0_var[i], a1b1_neg[i]); // 2*k+1 registers each
        imag_init[i] = long_add(n, 2*k, a0b1_var[i], a1b0_var[i]);
        imag_init_neg[i] = long_add(n, 2*k, a0b1_neg[i], a1b0_neg[i]);
    }
    std::size_t real_carry[l][50];
    std::size_t imag_carry[l][50];
    std::size_t real_final[l][50];
    std::size_t imag_final[l][50];
    std::size_t zeros[50]; // to balance register sizes
    for (int i = 0; i < 50; i ++) {
        zeros[i] = 0;
    }
    for (int i = 0; i < l; i ++) {
        if (i == l - 1) {
            real_carry[i] = long_add(n, 2*k+1, zeros, zeros);
            imag_carry[i] = long_add(n, 2*k+1, zeros, zeros);
        } else {
            real_carry[i] = long_add(n, 2*k+1, real_init[i+l], imag_init_neg[i+l]); // now 2*k+2 registers
            imag_carry[i] = long_add(n, 2*k+1, imag_init[i+l], real_init[i+l]);
        }
    }
    for (int i = 0; i < l; i ++) {
        real_final[i] = long_add_unequal(n, 2*k+2, 2*k+1, real_carry[i], real_init[i]); // now 2*k+3 registers
        imag_final[i] = long_add_unequal(n, 2*k+2, 2*k+1, imag_carry[i], imag_init[i]);
    }
    std::size_t XYreal_temp[l][2][50];
    std::size_t XYimag_temp[l][2][50];
    for (int i = 0; i < l; i ++) {
        XYreal_temp[i] = long_div2(n, k, k+3, real_final[i], p); // k+4 register quotient, k register remainder
        XYimag_temp[i] = long_div2(n, k, k+3, imag_final[i], p);
    }
    for (int i = 0; i < l; i ++) {
        for (std::size_t j = 0; j < k; j ++) {
            out[i][0][j] = XYreal_temp[i][1][j];
            out[i][1][j] = XYimag_temp[i][1][j];
        }
    }
    return out;
}

// a is 6 x 2 x k element of Fp^12
// compute inverse. first multiply by conjugate a + bw (a,b in Fp^6, w^6=1+u, u^2=-1)
// then reduce to inverting in Fp^6
function find_Fp12_inverse(n, k, p, a) {
    std::size_t A[6][2][50];
    std::size_t B[6][2][50];
    std::size_t Bw[6][2][50];
    for (int i = 0; i < 3; i ++) {
        for (std::size_t j = 0; j < 2; j ++) {
            for (std::size_t m = 0; m < k; m ++) {
                A[2*i+1][j][m] = 0;
                B[2*i+1][j][m] = 0;
                A[2*i][j][m] = a[2*i][j][m];
                B[2*i][j][m] = a[2*i+1][j][m];
                Bw[2*i][j][m] = 0;
                Bw[2*i+1][j][m] = a[2*i+1][j][m];
            }
        }
    }
    std::size_t A2[6][2][50] = find_Fp12_product(n, k, A, A, p);
    std::size_t B2[6][2][50] = find_Fp12_product(n, k, B, B, p);
    std::size_t conj[6][2][50] = find_Fp12_diff(n, k, A, Bw, p);
    std::size_t w2[6][2][50];
    for (int i = 0; i < 6; i ++) {
        for (std::size_t j = 0; j < 2; j ++) {
            for (std::size_t m = 0; m < k; m ++) {
                if (i == 2 && j == 0 && m == 0) {
                    w2[i][j][m] = 1;
                } else {
                    w2[i][j][m] = 0;
                }
            }
        }
    }
    std::size_t B2w2[6][2][50] = find_Fp12_product(n, k, B2, w2, p);
    std::size_t conjProd[6][2][50] = find_Fp12_diff(n, k, A2, B2w2, p);
    std::size_t a0[2][50];
    std::size_t a1[2][50];
    std::size_t a2[2][50];
    for (int i = 0; i < 2; i ++) {
        for (std::size_t m = 0; m < k; m ++) {
            a0[i][m] = conjProd[0][i][m];
            a1[i][m] = conjProd[2][i][m];
            a2[i][m] = conjProd[4][i][m];
        }
    }
    std::size_t conjProdInv[6][2][50] = find_Fp6_inverse(n, k, p, a0, a1, a2);
    std::size_t out[6][2][50] = find_Fp12_product(n, k, conj, conjProdInv, p);
    return out;
}

// compute the inverse of a0 + a1v + a2v^2 in Fp6, where 
// v^3 = 1+u, u^2 = -1, a0 a1 a2 in Fp2 (2 x k)
// returns an element in standard Fp12 representation (6 x 2 x k)
function find_Fp6_inverse(n, k, p, a0, a1, a2) {
    std::size_t out[6][2][50];

    std::size_t a0_squared[2][50] = find_Fp2_product(n, k, a0, a0, p);
    std::size_t a1_squared[2][50] = find_Fp2_product(n, k, a1, a1, p);
    std::size_t a2_squared[2][50] = find_Fp2_product(n, k, a2, a2, p);
    std::size_t a0a1[2][50] = find_Fp2_product(n, k, a0, a1, p);
    std::size_t a0a2[2][50] = find_Fp2_product(n, k, a0, a2, p);
    std::size_t a1a2[2][50] = find_Fp2_product(n, k, a1, a2, p);
    std::size_t a0a1a2[2][50] = find_Fp2_product(n, k, a0a1, a2, p);

    std::size_t v3[2][50]; // v^3 = 1 + u
    for (int i = 0; i < 2; i ++) {
        for (std::size_t j = 0; j < k; j ++) {
            if (j == 0) {
                v3[i][j] = 1;
            } else {
                v3[i][j] = 0;
            }
        }
    }

    std::size_t three_v3[2][50]; // 3v^3 = 3 + 3u
    for (int i = 0; i < 2; i ++) {
        for (std::size_t j = 0; j < k; j ++) {
            if (j == 0) {
                three_v3[i][j] = 3;
            } else {
                three_v3[i][j] = 0;
            }
        }
    }

    std::size_t v6[2][50]; // v^6 = 2u
    for (int i = 0; i < 2; i ++) {
        for (std::size_t j = 0; j < k; j ++) {
            if (i == 1 && j == 0) {
                v6[i][j] = 2;
            } else {
                v6[i][j] = 0;
            }
        }
    }

    std::size_t v0_1[2][50] = find_Fp2_product(n, k, a1a2, v3, p);
    std::size_t v0_temp[2][50] = find_Fp2_diff(n, k, a0_squared, v0_1, p); // a0^2 - a1a2v^3
    std::size_t v1_1[2][50] = find_Fp2_product(n, k, a2_squared, v3, p);
    std::size_t v1_temp[2][50] = find_Fp2_diff(n, k, v1_1, a0a1, p); // v^3a2^2 - a0a1
    std::size_t v2_temp[2][50] = find_Fp2_diff(n, k, a1_squared, a0a2, p); // a1^2 - a0a2

    std::size_t a0_cubed[2][50] = find_Fp2_product(n, k, a0, a0_squared, p);
    std::size_t a1_cubed[2][50] = find_Fp2_product(n, k, a1, a1_squared, p);
    std::size_t a2_cubed[2][50] = find_Fp2_product(n, k, a2, a2_squared, p);
    std::size_t a13v3[2][50] = find_Fp2_product(n, k, a1_cubed, v3, p);
    std::size_t a23v6[2][50] = find_Fp2_product(n, k, a2_cubed, v6, p);
    std::size_t a0a1a23v3[2][50] = find_Fp2_product(n, k, a0a1a2, three_v3, p);

    std::size_t denom_1[2][50] = find_Fp2_sum(n, k, a0_cubed, a13v3, p);
    std::size_t denom_2[2][50] = find_Fp2_diff(n, k, a23v6, a0a1a23v3, p);
    std::size_t denom[2][50] = find_Fp2_sum(n, k, denom_1, denom_2, p); // a0^3 + a1^3v^3 + a2^3v^6 - 3a0a1a2v^3

    std::size_t denom_inv[2][50] = find_Fp2_inverse(n, k, denom, p);

    std::size_t v0_final[2][50] = find_Fp2_product(n, k, v0_temp, denom_inv, p);
    std::size_t v1_final[2][50] = find_Fp2_product(n, k, v1_temp, denom_inv, p);
    std::size_t v2_final[2][50] = find_Fp2_product(n, k, v2_temp, denom_inv, p);

    for (std::size_t i = 1; i < 6; i = i + 2) {
        for (std::size_t j = 0; j < 2; j ++) {
            for (std::size_t m = 0; m < 50; m ++) {
                if (i > 1)
                out[i][j][m] = 0;
                else 
                out[i][j][m] = 0;//v3[j][m];
            }
        }
    }
    out[0] = v0_final;
    out[2] = v1_final;
    out[4] = v2_final;
    return out;
}

