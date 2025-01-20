#ifndef __CRYPTO_OPS_H
#define __CRYPTO_OPS_H

#include "main.h"
#include "mbedtls/aes.h"
#include "mbedtls/ecdh.h"
#include "stdbool.h"

// Declare variables that will be defined in crypto_ops.c
extern mbedtls_aes_context aes_packet_ctx;
extern mbedtls_aes_context aes_session_ctx;
extern mbedtls_aes_context aes_handshake_ctx;

extern uint8_t aes_packet_key[16];
extern uint8_t original_iv[16];
extern uint8_t aes_packet_iv[16];
extern uint8_t aes_handshake_key[16];
extern uint8_t aes_handshake_iv[16];

extern unsigned char public_key[65];
extern size_t public_key_len;
extern unsigned char peer_public_key[65];
extern size_t peer_public_key_len;
extern bool handshake_done;
extern bool secret_generated;
extern unsigned char session_aes_key[16];
extern unsigned char session_iv[16];

// Function declarations
void init_aes_context(mbedtls_aes_context *aes_ctx, uint8_t *key, uint8_t *iv);
void decrypt_data(mbedtls_aes_context *aes_ctx, uint8_t *iv, uint8_t *data, uint8_t data_length, uint8_t *decrypted_data);
void free_aes_context(mbedtls_aes_context *aes_ctx);
void reset_iv(void);
void get_hash(uint8_t *input, uint8_t *output, size_t size);

void ecdh_init(void);
int ecdh_gen_key_pair(unsigned char *public_key, size_t *public_key_len);
int stm32_rng_poll(void *data, unsigned char *output, size_t len, size_t *olen);
int ecdh_generate_shared_secret_uncompressed(const unsigned char *peer_uncompressed_key, size_t key_len, unsigned char *shared_secret, size_t secret_len);
int derive_aes_key_and_iv(unsigned char *shared_secret, size_t secret_len, unsigned char *aes_key, size_t aes_key_len, unsigned char *iv, size_t iv_len);

// New function to handle the entire shared secret and key derivation process
void handle_crypto_handshake(void);

#endif /* __CRYPTO_OPS_H */ 
