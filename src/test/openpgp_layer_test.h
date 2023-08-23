#ifndef OPENPGP_LAYER_TEST
#define OPENPGP_LAYER_TEST

#include "../openpgp_layer.h"
#include "openpgp_layer_test_constants.h"

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Runs a test of ECDH functionality.
     * @param[in] vector Pre-filled with expected values (random keypair v, VG, privkey, pubkey and the resulting shared secret).
     *
     */
    int openpgp_libecc_test_ecdh(const ecdh_test_value* vector);

    /**
     * Runs a test of ECDSA or EdDSA signature verification.
     * @param[in] input Pre-filled with expected values. Private key does not have to be specified, as verification doesn't require it. The message is expected to be nonempty.
     */
    int openpgp_libecc_test_ecdsa_verify(const ecdsa_params* input);

    /**
     * Tries to sign and verify a message with a given nonce.
     */
    int openpgp_libecc_test_ecdsa_sign_and_verify_cycle(const ecdsa_params* input);


#ifdef __cplusplus
}
#endif

#endif // !OPENPGP_LAYER_TEST
