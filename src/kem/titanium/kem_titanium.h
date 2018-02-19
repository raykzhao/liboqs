#ifndef __OQS_KEM_TITANIUM_H
#define __OQS_KEM_TITANIUM_H

#include <oqs/oqs.h>

#ifdef OQS_ENABLE_KEM_titanium_kmac_toy

#define OQS_KEM_titanium_kmac_toy_length_public_key 12192
#define OQS_KEM_titanium_kmac_toy_length_secret_key 12224
#define OQS_KEM_titanium_kmac_toy_length_ciphertext 2720
#define OQS_KEM_titanium_kmac_toy_length_shared_secret 32

OQS_KEM *OQS_KEM_titanium_kmac_toy_new();

extern OQS_STATUS OQS_KEM_titanium_kmac_toy_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_titanium_kmac_toy_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_titanium_kmac_toy_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#ifdef OQS_ENABLE_KEM_titanium_aes_toy

#define OQS_KEM_titanium_aes_toy_length_public_key 12192
#define OQS_KEM_titanium_aes_toy_length_secret_key 12224
#define OQS_KEM_titanium_aes_toy_length_ciphertext 2720
#define OQS_KEM_titanium_aes_toy_length_shared_secret 32

OQS_KEM *OQS_KEM_titanium_aes_toy_new();

extern OQS_STATUS OQS_KEM_titanium_aes_toy_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_titanium_aes_toy_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_titanium_aes_toy_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#ifdef OQS_ENABLE_KEM_titanium_kmac_lite

#define OQS_KEM_titanium_kmac_lite_length_public_key 14720
#define OQS_KEM_titanium_kmac_lite_length_secret_key 14752
#define OQS_KEM_titanium_kmac_lite_length_ciphertext 3008
#define OQS_KEM_titanium_kmac_lite_length_shared_secret 32

OQS_KEM *OQS_KEM_titanium_kmac_lite_new();

extern OQS_STATUS OQS_KEM_titanium_kmac_lite_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_titanium_kmac_lite_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_titanium_kmac_lite_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#ifdef OQS_ENABLE_KEM_titanium_aes_lite

#define OQS_KEM_titanium_aes_lite_length_public_key 14720
#define OQS_KEM_titanium_aes_lite_length_secret_key 14752
#define OQS_KEM_titanium_aes_lite_length_ciphertext 3008
#define OQS_KEM_titanium_aes_lite_length_shared_secret 32

OQS_KEM *OQS_KEM_titanium_aes_lite_new();

extern OQS_STATUS OQS_KEM_titanium_aes_lite_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_titanium_aes_lite_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_titanium_aes_lite_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#ifdef OQS_ENABLE_KEM_titanium_kmac_std

#define OQS_KEM_titanium_kmac_std_length_public_key 16352
#define OQS_KEM_titanium_kmac_std_length_secret_key 16384
#define OQS_KEM_titanium_kmac_std_length_ciphertext 3552
#define OQS_KEM_titanium_kmac_std_length_shared_secret 32

OQS_KEM *OQS_KEM_titanium_kmac_std_new();

extern OQS_STATUS OQS_KEM_titanium_kmac_std_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_titanium_kmac_std_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_titanium_kmac_std_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#ifdef OQS_ENABLE_KEM_titanium_aes_std

#define OQS_KEM_titanium_aes_std_length_public_key 16352
#define OQS_KEM_titanium_aes_std_length_secret_key 16384
#define OQS_KEM_titanium_aes_std_length_ciphertext 3552
#define OQS_KEM_titanium_aes_std_length_shared_secret 32

OQS_KEM *OQS_KEM_titanium_aes_std_new();

extern OQS_STATUS OQS_KEM_titanium_aes_std_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_titanium_aes_std_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_titanium_aes_std_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#ifdef OQS_ENABLE_KEM_titanium_kmac_med

#define OQS_KEM_titanium_kmac_med_length_public_key 18272
#define OQS_KEM_titanium_kmac_med_length_secret_key 18304
#define OQS_KEM_titanium_kmac_med_length_ciphertext 4544
#define OQS_KEM_titanium_kmac_med_length_shared_secret 32

OQS_KEM *OQS_KEM_titanium_kmac_med_new();

extern OQS_STATUS OQS_KEM_titanium_kmac_med_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_titanium_kmac_med_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_titanium_kmac_med_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#ifdef OQS_ENABLE_KEM_titanium_aes_med

#define OQS_KEM_titanium_aes_med_length_public_key 18272
#define OQS_KEM_titanium_aes_med_length_secret_key 18304
#define OQS_KEM_titanium_aes_med_length_ciphertext 4544
#define OQS_KEM_titanium_aes_med_length_shared_secret 32

OQS_KEM *OQS_KEM_titanium_aes_med_new();

extern OQS_STATUS OQS_KEM_titanium_aes_med_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_titanium_aes_med_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_titanium_aes_med_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#ifdef OQS_ENABLE_KEM_titanium_kmac_hi

#define OQS_KEM_titanium_kmac_hi_length_public_key 20512
#define OQS_KEM_titanium_kmac_hi_length_secret_key 20544
#define OQS_KEM_titanium_kmac_hi_length_ciphertext 6048
#define OQS_KEM_titanium_kmac_hi_length_shared_secret 32

OQS_KEM *OQS_KEM_titanium_kmac_hi_new();

extern OQS_STATUS OQS_KEM_titanium_kmac_hi_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_titanium_kmac_hi_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_titanium_kmac_hi_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#ifdef OQS_ENABLE_KEM_titanium_aes_hi

#define OQS_KEM_titanium_aes_hi_length_public_key 20512
#define OQS_KEM_titanium_aes_hi_length_secret_key 20544
#define OQS_KEM_titanium_aes_hi_length_ciphertext 6048
#define OQS_KEM_titanium_aes_hi_length_shared_secret 32

OQS_KEM *OQS_KEM_titanium_aes_hi_new();

extern OQS_STATUS OQS_KEM_titanium_aes_hi_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_titanium_aes_hi_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_titanium_aes_hi_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#ifdef OQS_ENABLE_KEM_titanium_kmac_super

#define OQS_KEM_titanium_kmac_super_length_public_key 26912
#define OQS_KEM_titanium_kmac_super_length_secret_key 26944
#define OQS_KEM_titanium_kmac_super_length_ciphertext 8352
#define OQS_KEM_titanium_kmac_super_length_shared_secret 32

OQS_KEM *OQS_KEM_titanium_kmac_super_new();

extern OQS_STATUS OQS_KEM_titanium_kmac_super_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_titanium_kmac_super_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_titanium_kmac_super_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#ifdef OQS_ENABLE_KEM_titanium_aes_super

#define OQS_KEM_titanium_aes_super_length_public_key 26912
#define OQS_KEM_titanium_aes_super_length_secret_key 26944
#define OQS_KEM_titanium_aes_super_length_ciphertext 8352
#define OQS_KEM_titanium_aes_super_length_shared_secret 32

OQS_KEM *OQS_KEM_titanium_aes_super_new();

extern OQS_STATUS OQS_KEM_titanium_aes_super_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_titanium_aes_super_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_titanium_aes_super_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#endif
