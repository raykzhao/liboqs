#include <stdlib.h>

#include <oqs/kem_titanium.h>

#ifdef OQS_ENABLE_KEM_titanium_kmac_toy

OQS_KEM *OQS_KEM_titanium_kmac_toy_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = "Titanium KMAC Toy";

	kem->claimed_nist_level = 0;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_titanium_kmac_toy_length_public_key;
	kem->length_secret_key = OQS_KEM_titanium_kmac_toy_length_secret_key;
	kem->length_ciphertext = OQS_KEM_titanium_kmac_toy_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_titanium_kmac_toy_length_shared_secret;

	kem->keypair = OQS_KEM_titanium_kmac_toy_keypair;
	kem->encaps = OQS_KEM_titanium_kmac_toy_encaps;
	kem->decaps = OQS_KEM_titanium_kmac_toy_decaps;

	return kem;
}

#endif

#ifdef OQS_ENABLE_KEM_titanium_aes_toy

OQS_KEM *OQS_KEM_titanium_aes_toy_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = "Titanium AES Toy";

	kem->claimed_nist_level = 0;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_titanium_aes_toy_length_public_key;
	kem->length_secret_key = OQS_KEM_titanium_aes_toy_length_secret_key;
	kem->length_ciphertext = OQS_KEM_titanium_aes_toy_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_titanium_aes_toy_length_shared_secret;

	kem->keypair = OQS_KEM_titanium_aes_toy_keypair;
	kem->encaps = OQS_KEM_titanium_aes_toy_encaps;
	kem->decaps = OQS_KEM_titanium_aes_toy_decaps;

	return kem;
}

#endif

#ifdef OQS_ENABLE_KEM_titanium_kmac_lite

OQS_KEM *OQS_KEM_titanium_kmac_lite_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = "Titanium KMAC Lite";

	kem->claimed_nist_level = 0;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_titanium_kmac_lite_length_public_key;
	kem->length_secret_key = OQS_KEM_titanium_kmac_lite_length_secret_key;
	kem->length_ciphertext = OQS_KEM_titanium_kmac_lite_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_titanium_kmac_lite_length_shared_secret;

	kem->keypair = OQS_KEM_titanium_kmac_lite_keypair;
	kem->encaps = OQS_KEM_titanium_kmac_lite_encaps;
	kem->decaps = OQS_KEM_titanium_kmac_lite_decaps;

	return kem;
}

#endif

#ifdef OQS_ENABLE_KEM_titanium_aes_lite

OQS_KEM *OQS_KEM_titanium_aes_lite_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = "Titanium AES Lite";

	kem->claimed_nist_level = 0;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_titanium_aes_lite_length_public_key;
	kem->length_secret_key = OQS_KEM_titanium_aes_lite_length_secret_key;
	kem->length_ciphertext = OQS_KEM_titanium_aes_lite_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_titanium_aes_lite_length_shared_secret;

	kem->keypair = OQS_KEM_titanium_aes_lite_keypair;
	kem->encaps = OQS_KEM_titanium_aes_lite_encaps;
	kem->decaps = OQS_KEM_titanium_aes_lite_decaps;

	return kem;
}

#endif

#ifdef OQS_ENABLE_KEM_titanium_kmac_std

OQS_KEM *OQS_KEM_titanium_kmac_std_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = "Titanium KMAC Std";

	kem->claimed_nist_level = 1;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_titanium_kmac_std_length_public_key;
	kem->length_secret_key = OQS_KEM_titanium_kmac_std_length_secret_key;
	kem->length_ciphertext = OQS_KEM_titanium_kmac_std_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_titanium_kmac_std_length_shared_secret;

	kem->keypair = OQS_KEM_titanium_kmac_std_keypair;
	kem->encaps = OQS_KEM_titanium_kmac_std_encaps;
	kem->decaps = OQS_KEM_titanium_kmac_std_decaps;

	return kem;
}

#endif

#ifdef OQS_ENABLE_KEM_titanium_aes_std

OQS_KEM *OQS_KEM_titanium_aes_std_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = "Titanium AES Std";

	kem->claimed_nist_level = 1;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_titanium_aes_std_length_public_key;
	kem->length_secret_key = OQS_KEM_titanium_aes_std_length_secret_key;
	kem->length_ciphertext = OQS_KEM_titanium_aes_std_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_titanium_aes_std_length_shared_secret;

	kem->keypair = OQS_KEM_titanium_aes_std_keypair;
	kem->encaps = OQS_KEM_titanium_aes_std_encaps;
	kem->decaps = OQS_KEM_titanium_aes_std_decaps;

	return kem;
}

#endif

#ifdef OQS_ENABLE_KEM_titanium_kmac_med

OQS_KEM *OQS_KEM_titanium_kmac_med_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = "Titanium KMAC Med";

	kem->claimed_nist_level = 0;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_titanium_kmac_med_length_public_key;
	kem->length_secret_key = OQS_KEM_titanium_kmac_med_length_secret_key;
	kem->length_ciphertext = OQS_KEM_titanium_kmac_med_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_titanium_kmac_med_length_shared_secret;

	kem->keypair = OQS_KEM_titanium_kmac_med_keypair;
	kem->encaps = OQS_KEM_titanium_kmac_med_encaps;
	kem->decaps = OQS_KEM_titanium_kmac_med_decaps;

	return kem;
}

#endif

#ifdef OQS_ENABLE_KEM_titanium_aes_med

OQS_KEM *OQS_KEM_titanium_aes_med_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = "Titanium AES Med";

	kem->claimed_nist_level = 0;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_titanium_aes_med_length_public_key;
	kem->length_secret_key = OQS_KEM_titanium_aes_med_length_secret_key;
	kem->length_ciphertext = OQS_KEM_titanium_aes_med_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_titanium_aes_med_length_shared_secret;

	kem->keypair = OQS_KEM_titanium_aes_med_keypair;
	kem->encaps = OQS_KEM_titanium_aes_med_encaps;
	kem->decaps = OQS_KEM_titanium_aes_med_decaps;

	return kem;
}

#endif

#ifdef OQS_ENABLE_KEM_titanium_kmac_hi

OQS_KEM *OQS_KEM_titanium_kmac_hi_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = "Titanium KMAC Hi";

	kem->claimed_nist_level = 3;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_titanium_kmac_hi_length_public_key;
	kem->length_secret_key = OQS_KEM_titanium_kmac_hi_length_secret_key;
	kem->length_ciphertext = OQS_KEM_titanium_kmac_hi_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_titanium_kmac_hi_length_shared_secret;

	kem->keypair = OQS_KEM_titanium_kmac_hi_keypair;
	kem->encaps = OQS_KEM_titanium_kmac_hi_encaps;
	kem->decaps = OQS_KEM_titanium_kmac_hi_decaps;

	return kem;
}

#endif

#ifdef OQS_ENABLE_KEM_titanium_aes_hi

OQS_KEM *OQS_KEM_titanium_aes_hi_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = "Titanium AES Hi";

	kem->claimed_nist_level = 3;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_titanium_aes_hi_length_public_key;
	kem->length_secret_key = OQS_KEM_titanium_aes_hi_length_secret_key;
	kem->length_ciphertext = OQS_KEM_titanium_aes_hi_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_titanium_aes_hi_length_shared_secret;

	kem->keypair = OQS_KEM_titanium_aes_hi_keypair;
	kem->encaps = OQS_KEM_titanium_aes_hi_encaps;
	kem->decaps = OQS_KEM_titanium_aes_hi_decaps;

	return kem;
}

#endif

#ifdef OQS_ENABLE_KEM_titanium_kmac_super

OQS_KEM *OQS_KEM_titanium_kmac_super_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = "Titanium KMAC Super";

	kem->claimed_nist_level = 5;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_titanium_kmac_super_length_public_key;
	kem->length_secret_key = OQS_KEM_titanium_kmac_super_length_secret_key;
	kem->length_ciphertext = OQS_KEM_titanium_kmac_super_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_titanium_kmac_super_length_shared_secret;

	kem->keypair = OQS_KEM_titanium_kmac_super_keypair;
	kem->encaps = OQS_KEM_titanium_kmac_super_encaps;
	kem->decaps = OQS_KEM_titanium_kmac_super_decaps;

	return kem;
}

#endif

#ifdef OQS_ENABLE_KEM_titanium_aes_super

OQS_KEM *OQS_KEM_titanium_aes_super_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = "Titanium AES Super";

	kem->claimed_nist_level = 5;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_titanium_aes_super_length_public_key;
	kem->length_secret_key = OQS_KEM_titanium_aes_super_length_secret_key;
	kem->length_ciphertext = OQS_KEM_titanium_aes_super_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_titanium_aes_super_length_shared_secret;

	kem->keypair = OQS_KEM_titanium_aes_super_keypair;
	kem->encaps = OQS_KEM_titanium_aes_super_encaps;
	kem->decaps = OQS_KEM_titanium_aes_super_decaps;

	return kem;
}

#endif
