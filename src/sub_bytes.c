#include "sub_bytes.h"
#include "aes.h"
#include "tables.h" // contient la Sbox

void SubBytes(AESState state) {
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < Nb; ++col) {
            state[row][col] = sbox[state[row][col]];
        }
    }
}

void InvSubBytes(AESState state) {
    extern const uint8_t inv_sbox[256];
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j)
            state[i][j] = inv_sbox[state[i][j]];
}