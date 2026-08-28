#include <strings.h>

#include "aes.h"
#include "sub_bytes.h"
#include "shift_rows.h"
#include "key_expansion.h"
#include "mix_columns.h"
#include "add_round_key.h"
#include "tables.h"


int Nb = 4;
int Nk = 4;
int Nr = 10;
int AES_KEY_SIZE = 16;
int AES_ROUND_KEY_SIZE = 176;



// Clés par défaut pour chaque taille
const uint8_t default_key_128[16] = {
    0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f
};

const uint8_t default_key_192[24] = {
    0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17
};

const uint8_t default_key_256[32] = {
    0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b, 0x1c,0x1d,0x1e,0x1f
};

// Pointeur vers la clé par défaut active (selon la taille)
const uint8_t *default_key = default_key_128;

void AES_set_key_size(int bits) {
    Nb = 4;
    if (bits == 128) {
        Nk = 4;
        Nr = 10;
        AES_KEY_SIZE = 16;
        AES_ROUND_KEY_SIZE = Nb * (Nr + 1) * 4; // 176
        default_key = default_key_128;
    } else if (bits == 192) {
        Nk = 6;
        Nr = 12;
        AES_KEY_SIZE = 24;
        AES_ROUND_KEY_SIZE = Nb * (Nr + 1) * 4; // 208
        default_key = default_key_192;
    } else if (bits == 256) {
        Nk = 8;
        Nr = 14;
        AES_KEY_SIZE = 32;
        AES_ROUND_KEY_SIZE = Nb * (Nr + 1) * 4; // 240
        default_key = default_key_256;
    } else {
        // Par défaut 128 bits si invalide
        Nk = 4;
        Nr = 10;
        AES_KEY_SIZE = 16;
        AES_ROUND_KEY_SIZE = Nb * (Nr + 1) * 4; // 176
        default_key = default_key_128;
    }
}


uint8_t iv[16] = {
    0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f
};




void AES_encrypt_block(const AESBlock in, AESBlock out, const AESRoundKeys roundKeys) {
    AESState state;
    int round;

    // copier les données du block d'entrée vers la matrice d'état (colonne par colonne)
    for (int col = 0; col < Nb; col++) {
        for (int row = 0; row < 4; row++) {
            state[row][col] = in[col*4 + row];
        }
    }
     // Ronde initiale (AddRoundKey)
     AddRoundKey(state, roundKeys); // roundKeys = w[0]

     // 9 rondes principales
     for (round = 1; round < Nr; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + Nb*round*4); // chaque round = 16 octets // décalage de round
     }

     // Dernière ronde (sans MixColumns)
     SubBytes(state);
     ShiftRows(state);
     AddRoundKey(state, roundKeys + Nr*Nb*4); // 160 = 10 * 16 = offset (décalage en octets) pour accéder à la dernière clé de ronde dans le tableau roundKeys

     // Copier la matrice d'état vers le bloc de sortie (colonne par colonne)
     for (int col = 0; col < Nb; col++) {
        for (int row = 0; row < 4; row++) {
            out[col*4 + row] = state[row][col];
        }
     }
}

void AES_decrypt_block(const AESBlock in, AESBlock out, const AESRoundKeys roundKeys) {
    AESState state;
    int round;

    // Copier les données du bloc d'entrée vers la matrice d'état (colonne par colonne)
    for (int col = 0; col < Nb; col++) {
        for (int row = 0; row < 4; row++) {
            state[row][col] = in[col * 4 + row];
        }
    }

    // Ronde initiale (clé de round Nr)
    AddRoundKey(state, roundKeys + Nr * Nb * 4);

    // Nr - 1 rondes principales (InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns)
    for (round = Nr - 1; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * Nb * 4);
        InvMixColumns(state);
    }

    // Dernière ronde (sans InvMixColumns)
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys); // round = 0

    // Copier la matrice d'état vers le bloc de sortie (colonne par colonne)
    for (int col = 0; col < Nb; col++) {
        for (int row = 0; row < 4; row++) {
            out[col * 4 + row] = state[row][col];
        }
    }
}






void AES_encrypt_CBC(const uint8_t *in, uint8_t *out, size_t len, const AESRoundKeys rk, uint8_t *iv) {
    uint8_t block[16];
    for (size_t i = 0; i < len; i += 16) {
        for (int j = 0; j < 16; j++) block[j] = in[i + j] ^ iv[j];
        AES_encrypt_block(block, out + i, rk);
        memcpy(iv, out + i, 16);
    }
}

void AES_decrypt_CBC(const uint8_t *in, uint8_t *out, size_t len, const AESRoundKeys rk, uint8_t *iv) {
    uint8_t block[16], tmp[16];
    for (size_t i = 0; i < len; i += 16) {
        memcpy(tmp, in + i, 16);
        AES_decrypt_block(in + i, block, rk);
        for (int j = 0; j < 16; j++) out[i + j] = block[j] ^ iv[j];
        memcpy(iv, tmp, 16);
    }
}

void AES_encrypt_CFB(const uint8_t *plaintext, uint8_t *ciphertext, size_t length, const AESRoundKeys roundKeys, uint8_t iv[16]) {
    uint8_t feedback[16];
    memcpy(feedback, iv, 16);

    for (size_t i = 0; i < length; i += 16) {
        uint8_t encrypted_feedback[16];
        AES_encrypt_block(feedback, encrypted_feedback, roundKeys);

        size_t block_size = (i + 16 <= length) ? 16 : length - i;

        for (size_t j = 0; j < block_size; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ encrypted_feedback[j];
        }

        memcpy(feedback, ciphertext + i, 16);
    }
}

void AES_decrypt_CFB(const uint8_t *ciphertext, uint8_t *plaintext, size_t length, const AESRoundKeys roundKeys, uint8_t iv[16]) {
    uint8_t feedback[16];
    memcpy(feedback, iv, 16);

    for (size_t i = 0; i < length; i += 16) {
        uint8_t encrypted_feedback[16];
        AES_encrypt_block(feedback, encrypted_feedback, roundKeys);

        size_t block_size = (i + 16 <= length) ? 16 : length - i;

        for (size_t j = 0; j < block_size; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ encrypted_feedback[j];
        }

        memcpy(feedback, ciphertext + i, 16);
    }
}



void AES_encrypt_OFB(const uint8_t *plaintext, uint8_t *ciphertext, size_t length, const AESRoundKeys roundKeys, uint8_t iv[16]) {
    uint8_t feedback[16];
    memcpy(feedback, iv, 16);

    for (size_t i = 0; i < length; i += 16) {
        AES_encrypt_block(feedback, feedback, roundKeys);  // update feedback by encrypting it

        size_t block_size = (i + 16 <= length) ? 16 : length - i;

        for (size_t j = 0; j < block_size; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ feedback[j];
        }
    }
}

void AES_decrypt_OFB(const uint8_t *ciphertext, uint8_t *plaintext, size_t length, const AESRoundKeys roundKeys, uint8_t iv[16]) {
    // En mode OFB, le déchiffrement est identique au chiffrement
    // On génère le flux de clé en chiffrant le vecteur de feedback (IV initialement)
    uint8_t feedback[16];
    memcpy(feedback, iv, 16);

    for (size_t i = 0; i < length; i += 16) {
        AES_encrypt_block(feedback, feedback, roundKeys);  // Met à jour le feedback

        size_t block_size = (i + 16 <= length) ? 16 : length - i;

        for (size_t j = 0; j < block_size; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ feedback[j];
        }
    }
}

// Pour CFB et OFB, déchiffrement = chiffrement.


// Fonction pour ajouter padding PKCS#7
uint8_t* add_padding(const uint8_t *input, size_t input_len, size_t *padded_len) {
    size_t pad_len = 16 - (input_len % 16);
    *padded_len = input_len + pad_len;
    uint8_t *padded = malloc(*padded_len);
    if (!padded) return NULL;

    memcpy(padded, input, input_len);
    // Remplir avec la valeur du padding (ex: 0x04 0x04 0x04 0x04 si 4 octets à ajouter)
    memset(padded + input_len, pad_len, pad_len);
    return padded;
}

// Fonction pour enlever padding PKCS#7
size_t remove_padding(uint8_t *data, size_t data_len) {
    if (data_len == 0) return 0;
    uint8_t pad_len = data[data_len - 1];
    if (pad_len > 16 || pad_len == 0) return data_len;  // padding invalide, on renvoie taille complète

    // Vérification simple du padding
    for (size_t i = data_len - pad_len; i < data_len; i++) {
        if (data[i] != pad_len) return data_len; // padding invalide
    }
    return data_len - pad_len;
}

// Convertit une chaîne hex (ex: "0a1b2c...") en tableau d'octets
// Retourne 0 si succès, -1 si erreur
int hexstr_to_bytes(const char *hexstr, uint8_t *bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; i++) {
        char byte_str[3] = { hexstr[2*i], hexstr[2*i+1], 0 };
        char *endptr;
        long val = strtol(byte_str, &endptr, 16);
        if (*endptr != '\0' || val < 0 || val > 0xFF) return -1;
        bytes[i] = (uint8_t)val;
    }
    return 0;
}

// Vérifie que la chaîne est une clé hex valide de 32 caractères
int is_valid_hex_key(const char *str, size_t expected_len) {
    if (strlen(str) != expected_len) return 0;
    for (size_t i = 0; i < expected_len; i++) {
        if (!isxdigit((unsigned char)str[i])) return 0;
    }
    return 1;
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <fichier_texte_clair>\n", argv[0]);
        return 1;
    }

    // Choix du mode de chiffrement/déchiffrement :
    char mode_str[4];
    int mode = 0; // 1 = ECB, 2 = CBC, 3 = CFB, 4 = OFB, 5 = GCM

    do {
        printf("Choisissez le mode de chiffrement (ECB, CBC, CFB, OFB, GCM) : ");
        scanf("%3s", mode_str);
        while (getchar() != '\n'); // flush stdin

        if (strcasecmp(mode_str, "ECB") == 0) mode = 1;
        else if (strcasecmp(mode_str, "CBC") == 0) mode = 2;
        else if (strcasecmp(mode_str, "CFB") == 0) mode = 3;
        else if (strcasecmp(mode_str, "OFB") == 0) mode = 4;
        else if (strcasecmp(mode_str, "GCM") == 0) mode = 5;

    } while (mode == 0);

    // Choix taille clé AES
    int key_bits = 0;
    do {
        printf("Choisissez la taille de la clé AES (128, 192 ou 256) : ");
        if (scanf("%d", &key_bits) != 1) {
            while (getchar() != '\n'); // vider stdin
            key_bits = 0;
            continue;
        }
        while (getchar() != '\n');
    } while (key_bits != 128 && key_bits != 192 && key_bits != 256);

    AES_set_key_size(key_bits); // Configure Nk, Nr, AES_KEY_SIZE

    uint8_t key[AES_KEY_SIZE];

    printf("Voulez-vous entrer une clé AES %d bits personnalisée ? (o/N) ", key_bits);
    char answer = getchar();
    while (getchar() != '\n');

    if (answer == 'o' || answer == 'O') {
        char input_key[65];
        int valid = 0;
        size_t expected_hex_len = AES_KEY_SIZE * 2;
        do {
            printf("Entrez la clé AES %d bits en hex (%zu caractères) :\n> ", key_bits, expected_hex_len);
            if (!fgets(input_key, sizeof(input_key), stdin)) {
                fprintf(stderr, "Erreur lecture clé\n");
                return 1;
            }
            input_key[strcspn(input_key, "\r\n")] = 0;

            if (strlen(input_key) != expected_hex_len || !is_valid_hex_key(input_key, expected_hex_len)) {
                printf("Clé invalide : doit contenir exactement %zu caractères hexadécimaux [0-9a-fA-F].\n", expected_hex_len);
                printf("Voulez-vous réessayer ? (o/N) ");
                char retry = getchar();
                while (getchar() != '\n');
                if (retry != 'o' && retry != 'O') {
                    printf("Utilisation de la clé par défaut.\n");
                    memcpy(key, default_key, AES_KEY_SIZE);
                    valid = 1;
                }
            } else {
                if (hexstr_to_bytes(input_key, key, AES_KEY_SIZE) != 0) {
                    fprintf(stderr, "Erreur conversion clé hex.\n");
                    return 1;
                }
                printf("Clé personnalisée acceptée.\n");
                valid = 1;
            }
        } while (!valid);
    } else {
        memcpy(key, default_key, AES_KEY_SIZE);
        printf("Utilisation de la clé par défaut.\n");
    }

    const char *input_filename = argv[1];
    char encrypted_filename[256];
    char decrypted_filename[256];

    snprintf(encrypted_filename, sizeof(encrypted_filename), "%s.enc", input_filename);
    snprintf(decrypted_filename, sizeof(decrypted_filename), "%s.dec", input_filename);

    FILE *f_in = fopen(input_filename, "rb");
    if (!f_in) {
        perror("Erreur ouverture fichier clair");
        return 1;
    }

    fseek(f_in, 0, SEEK_END);
    long filesize = ftell(f_in);
    rewind(f_in);

    if (filesize < 0) {
        fprintf(stderr, "Erreur taille fichier\n");
        fclose(f_in);
        return 1;
    }

    uint8_t *input_data = malloc(filesize);
    if (!input_data) {
        fprintf(stderr, "Erreur allocation mémoire\n");
        fclose(f_in);
        return 1;
    }

    fread(input_data, 1, filesize, f_in);
    fclose(f_in);

    size_t padded_len;
    uint8_t *padded_data = add_padding(input_data, filesize, &padded_len);
    if (!padded_data) {
        fprintf(stderr, "Erreur allocation mémoire pour padding\n");
        free(input_data);
        return 1;
    }

    uint8_t *encrypted = malloc(padded_len);
    uint8_t *decrypted = malloc(padded_len);
    if (!encrypted || !decrypted) {
        fprintf(stderr, "Erreur allocation mémoire\n");
        free(padded_data);
        free(encrypted);
        free(decrypted);
        free(input_data);
        return 1;
    }

    AESRoundKeys roundKeys;
    KeyExpansion(key, roundKeys);

    uint8_t iv_enc[16], iv_dec[16];
    memcpy(iv_enc, iv, 16);
    memcpy(iv_dec, iv, 16);

    if (mode == 1) {
        for (size_t i = 0; i < padded_len; i += 16)
            AES_encrypt_block(padded_data + i, encrypted + i, roundKeys);
    } else if (mode == 2) {
        AES_encrypt_CBC(padded_data, encrypted, padded_len, roundKeys, iv_enc) ;
    } else if (mode == 3) {
        AES_encrypt_CFB(padded_data, encrypted, padded_len, roundKeys, iv_enc);
    } else if (mode == 4) {
        AES_encrypt_OFB(padded_data, encrypted, padded_len, roundKeys, iv_enc);
    } else if (mode == 5) {
        fprintf(stderr, "GCM non encore implémenté.\n");
        exit(1);
    }


    FILE *f_enc = fopen(encrypted_filename, "wb");
    if (!f_enc) {
        perror("Erreur création fichier chiffré");
        free(padded_data);
        free(encrypted);
        free(decrypted);
        free(input_data);
        return 1;
    }
    fwrite(encrypted, 1, padded_len, f_enc);
    fclose(f_enc);

    printf("Fichier chiffré sauvegardé dans '%s'\n", encrypted_filename);

    if (mode == 1) {
        for (size_t i = 0; i < padded_len; i += 16)
            AES_decrypt_block(encrypted + i, decrypted + i, roundKeys);
    } else if (mode == 2) {
        AES_decrypt_CBC(encrypted, decrypted, padded_len, roundKeys, iv_dec);
    } else if (mode == 3) {
        AES_decrypt_CFB(encrypted, decrypted, padded_len, roundKeys, iv_dec);
    } else if (mode == 4) {
        AES_decrypt_OFB(encrypted, decrypted, padded_len, roundKeys, iv_dec); // idem OFB/CFB
    }

    size_t decrypted_len = remove_padding(decrypted, padded_len);

    FILE *f_dec = fopen(decrypted_filename, "wb");
    if (!f_dec) {
        perror("Erreur création fichier déchiffré");
        free(padded_data);
        free(encrypted);
        free(decrypted);
        free(input_data);
        return 1;
    }
    fwrite(decrypted, 1, decrypted_len, f_dec);
    fclose(f_dec);

    printf("Fichier déchiffré sauvegardé dans '%s'\n", decrypted_filename);

    if ((size_t)filesize == decrypted_len && memcmp(decrypted, input_data, (size_t)filesize) == 0) {
        printf("Succès : le déchiffrement correspond au texte clair initial.\n");
    } else {
        printf("Erreur : le déchiffrement ne correspond PAS au texte clair initial.\n");
    }

    printf("Mesure du temps pour 100 encryptions du fichier '%s' avec la clé choisie ...\n", input_filename);
    clock_t start = clock();
    for (int repeat = 0; repeat < 100; repeat++) {
        for (size_t i = 0; i < padded_len; i += 16) {
            AES_encrypt_block(padded_data + i, encrypted + i, roundKeys);
        }
    }
    clock_t end = clock();
    double time_sec = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Temps total pour 100 encryptions : %.3f secondes\n", time_sec);

    free(padded_data);
    free(encrypted);
    free(decrypted);
    free(input_data);

    return 0;
}