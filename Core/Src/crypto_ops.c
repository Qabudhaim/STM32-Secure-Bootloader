#include "crypto_ops.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"
#include "usb_comm.h"
#include "uart_comm.h"
#include <string.h>

// Global variables
mbedtls_aes_context aes_packet_ctx;
mbedtls_aes_context aes_session_ctx;
mbedtls_aes_context aes_handshake_ctx;

uint8_t aes_packet_key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

uint8_t original_iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

uint8_t aes_packet_iv[16] = { 0 };

uint8_t aes_handshake_key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

uint8_t aes_handshake_iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

mbedtls_ecdh_context ecdh;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

unsigned char public_key[65];
size_t public_key_len = sizeof(public_key);
unsigned char peer_public_key[65];
size_t peer_public_key_len = sizeof(peer_public_key);
bool handshake_done = false;
bool secret_generated = false;
unsigned char session_aes_key[16];
unsigned char session_iv[16];

extern RNG_HandleTypeDef hrng;

void init_aes_context(mbedtls_aes_context *aes_ctx, uint8_t *key, uint8_t *iv) {
    mbedtls_aes_setkey_dec(aes_ctx, key, 128);
}

void decrypt_data(mbedtls_aes_context *aes_ctx, uint8_t *iv, uint8_t *data,
                 uint8_t data_length, uint8_t *decrypted_data) {
    mbedtls_aes_crypt_cbc(aes_ctx, MBEDTLS_AES_DECRYPT, data_length, iv, data,
                          decrypted_data);
}

void free_aes_context(mbedtls_aes_context *aes_ctx) {
    mbedtls_aes_free(aes_ctx);
}

void reset_iv(void) {
    memcpy(aes_packet_iv, original_iv, 16);
}

void get_hash(uint8_t *input, uint8_t *output, size_t size) {
    mbedtls_md_context_t md_ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, input, size);
    mbedtls_md_finish(&md_ctx, output);
    mbedtls_md_free(&md_ctx);
}

void ecdh_init(void) {
    mbedtls_ecdh_init(&ecdh);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_add_source(&entropy, stm32_rng_poll, &hrng, 32,
                              MBEDTLS_ENTROPY_SOURCE_STRONG);

    const char *pers = "ecdh_example";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char*)pers, strlen(pers));

    mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_SECP256R1);
}

int ecdh_gen_key_pair(unsigned char *public_key, size_t *public_key_len) {
    int ret = mbedtls_ecdh_gen_public(&ecdh.grp, &ecdh.d, &ecdh.Q,
                                     mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_ecp_point_write_binary(&ecdh.grp, &ecdh.Q,
                                        MBEDTLS_ECP_PF_UNCOMPRESSED,
                                        public_key_len, public_key, *public_key_len);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int stm32_rng_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    RNG_HandleTypeDef *hrng = (RNG_HandleTypeDef*)data;
    if (HAL_RNG_GenerateRandomNumber(hrng, (uint32_t*)output) != HAL_OK) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    *olen = len;
    return 0;
}

int ecdh_generate_shared_secret_uncompressed(const unsigned char *peer_uncompressed_key,
                                           size_t key_len,
                                           unsigned char *shared_secret,
                                           size_t secret_len) {
    int ret;
    mbedtls_ecp_point peer_public_key;

    if (key_len != 65 || peer_uncompressed_key[0] != 0x04) {
        return -1;
    }

    mbedtls_ecp_point_init(&peer_public_key);

    ret = mbedtls_ecp_point_read_binary(&ecdh.grp, &peer_public_key,
                                       peer_uncompressed_key, key_len);
    if (ret != 0) {
        mbedtls_ecp_point_free(&peer_public_key);
        return ret;
    }

    ret = mbedtls_ecdh_compute_shared(&ecdh.grp, &ecdh.z, &peer_public_key, &ecdh.d,
                                     mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        mbedtls_ecp_point_free(&peer_public_key);
        return ret;
    }

    ret = mbedtls_mpi_write_binary(&ecdh.z, shared_secret, secret_len);
    if (ret != 0) {
        mbedtls_ecp_point_free(&peer_public_key);
        return ret;
    }

    mbedtls_ecp_point_free(&peer_public_key);
    return 0;
}

int derive_aes_key_and_iv(unsigned char *shared_secret, size_t secret_len,
                          unsigned char *aes_key, size_t aes_key_len,
                          unsigned char *iv, size_t iv_len) {
    int ret;

    // Validate key and IV lengths (AES-128 requires 16 bytes for key and IV)
    if (aes_key_len != 16 || iv_len != 16) {
        return -1;
    }

    // Derive 32 bytes of key material (16 bytes for AES key + 16 bytes for IV)
    unsigned char key_material[32];
    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                       NULL, 0, // No salt
                       shared_secret, secret_len,
                       NULL, 0, // No info
                       key_material, sizeof(key_material));
    if (ret != 0) {
        return ret;
    }

    // Split the key material into AES key and IV
    memcpy(aes_key, key_material, aes_key_len);
    memcpy(iv, key_material + aes_key_len, iv_len);

    return 0;
}

//int derive_aes_key_and_iv(unsigned char *shared_secret, size_t secret_len,
//                         unsigned char *aes_key, size_t aes_key_len,
//                         unsigned char *iv, size_t iv_len) {
//    int ret;
//    const unsigned char salt[] = "example_salt";
//    const unsigned char info[] = "aes_key_iv_derivation";
//
//    if (aes_key_len != 16 || iv_len != 16) {
//        return -1;
//    }
//
//    unsigned char key_material[32];
//    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
//                       salt, sizeof(salt),
//                       shared_secret, secret_len,
//                       info, sizeof(info),
//                       key_material, sizeof(key_material));
//    if (ret != 0) {
//        return ret;
//    }
//
//    memcpy(aes_key, key_material, aes_key_len);
//    memcpy(iv, key_material + aes_key_len, iv_len);
//
//    return 0;
//}

void handle_crypto_handshake(void) {
    if (handshake_done && !secret_generated) {
        unsigned char shared_secret[32];
        size_t shared_secret_len = sizeof(shared_secret);

        if (ecdh_generate_shared_secret_uncompressed(peer_public_key, peer_public_key_len, 
                                                   shared_secret, shared_secret_len) == 0) {
            
            if (derive_aes_key_and_iv(shared_secret, sizeof(shared_secret),
                                     session_aes_key, sizeof(session_aes_key),
                                     session_iv, sizeof(session_iv)) == 0) {
                
                init_aes_context(&aes_session_ctx, session_aes_key, session_iv);
                secret_generated = true;
                usb_ack(NULL, 0);
                uart_ack(NULL, 0);
            }
        }
    }
}
