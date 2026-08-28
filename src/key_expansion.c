#include "key_expansion.h"
#include "aes.h"
#include "tables.h" // contient la Sbox et les constantes de ronde Rcon


// ---------------------------------------------------------------------------------------------
// Fonctions utilitaires sur les mots
// ---------------------------------------------------------------------------------------------

// Décale un mot de 32 bits vers la gauche d'un octet (RotWord)
static word RotWord(word w) {
    return (w << 8) | (w >> 24);
}

// Applique la S-box à chaque octet du mot (SubWord)
static word SubWord(word w) {
    return (sbox[(w >> 24) & 0xFF] << 24) |
           (sbox[(w >> 16) & 0xFF] << 16) |
           (sbox[(w >> 8)  & 0xFF] << 8)  |
           (sbox[(w)       & 0xFF]);
}

// ---------------------------------------------------------------------------------------------
// Key Expension AES-128 (fidèle au pseudo-code FIPS-197 mais en utilisant plutôt des boucles for que des while)
// ---------------------------------------------------------------------------------------------
void KeyExpansion(const uint8_t* key, AESRoundKeys roundKeys) {
    // pas besoin d'ajouter const in Nk = 4 (ainsi que pour Nb = 4 et Nr = 10) car déjà définis dans aes.h
    word w[Nb * (Nr+1)]; // soit 4*11 = 44 mots
    word temp; // mot temporaire pour stocker
    int i;
    for (i=0; i < Nk; i++) {
        w[i] = (key[4 * i] << 24) |
               (key[4 * i + 1] << 16) |
               (key[4 * i + 2] << 8) |
               (key[4 * i + 3]);
    }

    // Générer les mots suivants
    for (i = Nk; i < Nb * (Nr + 1); i++) {
        temp = w[i - 1];
        if (i % Nk == 0) {
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
        }
        w[i] = w[i - Nk] ^ temp;
    }

    // Copier les mots w[] dans roundKeys[] (sous forme de tableau d'octets)
    for (i = 0; i < Nb * (Nr + 1); i++) {
        roundKeys[4 * i]     = (w[i] >> 24) & 0xFF;
        roundKeys[4 * i + 1] = (w[i] >> 16) & 0xFF;
        roundKeys[4 * i + 2] = (w[i] >> 8)  & 0xFF;
        roundKeys[4 * i + 3] = (w[i])       & 0xFF;
    }
}