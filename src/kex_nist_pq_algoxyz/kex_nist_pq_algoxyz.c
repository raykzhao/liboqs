#include <kex_nist_pq_algoxyz.h>

#include <string.h>
#include <stdlib.h>
#include <oqs/kex.h>

#if defined(WINDOWS)
#define UNUSED
// __attribute__ not supported in VS
#else
#define UNUSED __attribute__((unused))
#endif

OQS_KEX *OQS_KEX_nist_pq_algoxyz_new(OQS_RAND *rand) {
	OQS_KEX *k = malloc(sizeof(OQS_KEX));
	if (k == NULL)
		return NULL;
	k->method_name = strdup("NIST_ALGOXYZ");
	k->estimated_classical_security = 256;
	k->estimated_quantum_security = 128;
	k->rand = rand;
	k->params = NULL;
	k->alice_0 = &OQS_KEX_nist_pq_algoxyz_alice_0;
	k->bob = &OQS_KEX_nist_pq_algoxyz_bob;
	k->alice_1 = &OQS_KEX_nist_pq_algoxyz_alice_1;
	k->alice_priv_free = &OQS_KEX_nist_pq_algoxyz_alice_priv_free;
	k->free = &OQS_KEX_nist_pq_algoxyz_free;
	return k;
}

typedef struct OQS_KEX_nist_pq_algoxyz_alice_priv {
	uint16_t priv_key_len;
	uint8_t *priv_key;
} OQS_KEX_nist_pq_algoxyz_alice_priv;

int OQS_KEX_nist_pq_algoxyz_alice_0(UNUSED OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len) {

	int ret = 0;
	uint32_t rc;
	OQS_KEX_nist_pq_algoxyz_alice_priv *nist_pq_algoxyz_alice_priv = NULL;

	*alice_priv = NULL;
	*alice_msg = NULL;

	/* allocate private key */
	nist_pq_algoxyz_alice_priv = malloc(sizeof(OQS_KEX_nist_pq_algoxyz_alice_priv));
	if (nist_pq_algoxyz_alice_priv == NULL)
		goto err;
	nist_pq_algoxyz_alice_priv->priv_key = NULL;
	*alice_priv = nist_pq_algoxyz_alice_priv;

	*alice_msg_len = (size_t) CRYPTO_PUBLICKEYBYTES;

	/* allocate private key bytes */
	nist_pq_algoxyz_alice_priv->priv_key_len = CRYPTO_SECRETKEYBYTES;
	nist_pq_algoxyz_alice_priv->priv_key = malloc(nist_pq_algoxyz_alice_priv->priv_key_len);
	if (nist_pq_algoxyz_alice_priv->priv_key == NULL)
		goto err;
	/* allocate public key */
	*alice_msg = malloc(*alice_msg_len);
	if (*alice_msg == NULL)
		goto err;

	/* generate public/private key pair */
	rc = crypto_kem_keypair(*alice_msg, nist_pq_algoxyz_alice_priv->priv_key);
	if (rc != 0)
		goto err;

	ret = 1;
	goto cleanup;

err:
	ret = 0;
	if (nist_pq_algoxyz_alice_priv != NULL)
		free(nist_pq_algoxyz_alice_priv->priv_key);
	free(nist_pq_algoxyz_alice_priv);
	*alice_priv = NULL;
	free(*alice_msg);
	*alice_msg = NULL;
cleanup:

	return ret;
}

int OQS_KEX_nist_pq_algoxyz_bob(UNUSED OQS_KEX *k, const uint8_t *alice_msg, UNUSED const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len) {

	int ret;
	uint32_t rc;

	*bob_msg = NULL;
	*key = NULL;

	/* generate random session key */
	*key_len = CRYPTO_BYTES;
	*key = malloc(*key_len);
	if (*key == NULL)
		goto err;

	/* calculate length of ciphertext */
	*bob_msg_len = (size_t) CRYPTO_CIPHERTEXTBYTES;

	/* allocate ciphertext */
	*bob_msg = malloc(*bob_msg_len);
	if (*bob_msg == NULL)
		goto err;

	/* encrypt session key */
	rc = crypto_kem_enc(*bob_msg, *key, alice_msg);
	if (rc != 0)
		goto err;

	ret = 1;
	goto cleanup;

err:
	ret = 0;
	free(*bob_msg);
	*bob_msg = NULL;
	free(*key);
	*key = NULL;
cleanup:

	return ret;
}

int OQS_KEX_nist_pq_algoxyz_alice_1(UNUSED OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, UNUSED const size_t bob_msg_len, uint8_t **key, size_t *key_len) {

	int ret;
	uint32_t rc;

	*key = NULL;

	OQS_KEX_nist_pq_algoxyz_alice_priv *nist_pq_algoxyz_alice_priv = (OQS_KEX_nist_pq_algoxyz_alice_priv *) alice_priv;

	/* allocate session key */
	*key_len = (size_t) CRYPTO_BYTES;
	*key = malloc(*key_len);
	if (*key == NULL)
		goto err;

	/* decrypt session key */
	rc = crypto_kem_dec(*key, bob_msg, nist_pq_algoxyz_alice_priv->priv_key);
	if (rc != 0)
		goto err;

	ret = 1;
	goto cleanup;

err:
	ret = 0;
	free(*key);
	*key = NULL;
cleanup:

	return ret;
}

void OQS_KEX_nist_pq_algoxyz_alice_priv_free(UNUSED OQS_KEX *k, void *alice_priv) {
	if (alice_priv) {
		OQS_KEX_nist_pq_algoxyz_alice_priv *nist_pq_algoxyz_alice_priv = (OQS_KEX_nist_pq_algoxyz_alice_priv *) alice_priv;
		free(nist_pq_algoxyz_alice_priv->priv_key);
	}
	free(alice_priv);
}

void OQS_KEX_nist_pq_algoxyz_free(OQS_KEX *k) {
	if (k)
		free(k->method_name);
	free(k);
}
