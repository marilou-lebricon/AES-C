
#ifndef AES_H
#define AES_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

// VARIABLES GLOBALES MODIFIABLES
extern int Nb; // Nombre de colonnes (toujours 4 pour AES)
extern int Nk; // Taille de la clé en mots (4, 6 ou 8)
extern int Nr; // Nombre de rounds (10, 12 ou 14)
extern int AES_KEY_SIZE; // Taille de la clé en octets : 16, 24 ou 32
extern int AES_ROUND_KEY_SIZE; // Taille totale des clés de round

// TYPES
typedef uint8_t AESBlock[16]; // 1 bloc AES = 128 bits = 16 octets
typedef uint8_t AESState[4][4];
typedef uint32_t word;

// Clé de round, à taille maximale
typedef uint8_t AESRoundKeys[240]; // Max possible pour AES-256

// CLÉS PAR DÉFAUT
extern const uint8_t default_key_128[16];
extern const uint8_t default_key_192[24];
extern const uint8_t default_key_256[32];
extern const uint8_t *default_key; // pointeur dynamique vers la bonne

// FONCTIONS
void AES_set_key_size(int key_bits);

void AES_encrypt_block(const AESBlock in, AESBlock out, const AESRoundKeys roundKeys);
void AES_decrypt_block(const AESBlock in, AESBlock out, const AESRoundKeys roundKeys);
void AES_encrypt_CBC(const uint8_t *in, uint8_t *out, size_t len, const AESRoundKeys rk, uint8_t *iv);
void AES_decrypt_CBC(const uint8_t *in, uint8_t *out, size_t len, const AESRoundKeys rk, uint8_t *iv);
void AES_encrypt_CFB(const uint8_t *plaintext, uint8_t *ciphertext, size_t length, const AESRoundKeys roundKeys, uint8_t iv[16]);
void AES_decrypt_CFB(const uint8_t *plaintext, uint8_t *ciphertext, size_t length, const AESRoundKeys roundKeys, uint8_t iv[16]);
void AES_encrypt_OFB(const uint8_t *plaintext, uint8_t *ciphertext, size_t length, const AESRoundKeys roundKeys, uint8_t iv[16]);
void AES_decrypt_OFB(const uint8_t *plaintext, uint8_t *ciphertext, size_t length, const AESRoundKeys roundKeys, uint8_t iv[16]);

uint8_t* add_padding(const uint8_t *input, size_t input_len, size_t *padded_len);
size_t remove_padding(uint8_t *data, size_t data_len);
int hexstr_to_bytes(const char *hexstr, uint8_t *bytes, size_t bytes_len);
int is_valid_hex_key(const char *str, size_t expected_len);

#endif // AES_H