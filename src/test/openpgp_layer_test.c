#include "../openpgp_layer.h"
#include "openpgp_layer_test.h"
#include <libecc/utils/utils.h>


int openpgp_libecc_test_ecdh(const ecdh_test_value* vector) {
	if ((vector == NULL) || (vector->expected_result->shared_secret_len == 0) || (vector->input->static_pubkey_len == 0)) {
		return KOpenPGPEllipticTest_MissingTestVectorDefinitions;
	}
	ecdh_result run_target;
	local_memset(&run_target, 0, sizeof(ecdh_result));	
	/* We will copy ephemeral private key in order to have a reproducible shared secret. */
	local_memcpy(run_target.ephemeral_privkey, vector->expected_result->ephemeral_privkey, vector->expected_result->ephemeral_privkey_len);
	run_target.ephemeral_privkey_len = vector->expected_result->ephemeral_privkey_len;
	int res = openpgp_libecc_ecdh_generate_keypair_and_shared_secret(&run_target, vector->input);
	if (res != KOpenPGPElliptic_OK) {
		return res;
	}
	/* The resulting ephemeral public key must be equal. */
	if (run_target.ephemeral_pubkey_len != vector->expected_result->ephemeral_pubkey_len) {
		return KOpenPGPEllipticTest_EphemeralPublicKeyLengthMismatch;
	}
	if (run_target.ephemeral_pubkey_len == 0) {
		return KOpenPGPEllipticTest_EphemeralPublicKeyUndefined;
	}
	if (openpgp_libecc_memcmp(run_target.ephemeral_pubkey, vector->expected_result->ephemeral_pubkey, run_target.ephemeral_pubkey_len) != 0) {
		return KOpenPGPEllipticTest_EphemeralPublicKeyContentMismatch;
	}
	/* The resulting shared secret must be equal. */
	if (run_target.shared_secret_len != vector->expected_result->shared_secret_len) {
		return KOpenPGPEllipticTest_SharedSecretLengthMismatch;
	}
	if (run_target.shared_secret_len == 0) {
		return KOpenPGPEllipticTest_SharedSecretUndefined;
	}
	if (openpgp_libecc_memcmp(run_target.shared_secret, vector->expected_result->shared_secret, run_target.shared_secret_len) != 0) {
		return KOpenPGPEllipticTest_SharedSecretContentMismatch;
	}
	if (vector->input->static_privkey_len != 0) {
		ecdh_result reconstruct_target;
		local_memset(&reconstruct_target, 0, sizeof(ecdh_result));
		int res2 = openpgp_libecc_ecdh_reconstruct_shared_secret(&reconstruct_target, vector->input);
		if (res2 != KOpenPGPElliptic_OK) {
			return res2;
		}
		if (reconstruct_target.shared_secret_len != vector->expected_result->shared_secret_len) {
			return KOpenPGPEllipticTest_SharedSecretLengthMismatch;
		}
		if (reconstruct_target.shared_secret_len == 0) {
			return KOpenPGPEllipticTest_SharedSecretUndefined;
		}
		if (openpgp_libecc_memcmp(reconstruct_target.shared_secret, vector->expected_result->shared_secret, reconstruct_target.shared_secret_len) != 0) {
			return KOpenPGPEllipticTest_SharedSecretContentMismatch; 
		}
	}
	return KOpenPGPEllipticTest_OK;
}

int openpgp_libecc_test_ecdsa_verify(const ecdsa_params* input) {
	if ((input == NULL) || (input->static_pubkey_len == 0) || (input->m_len == 0) || (input->r_len == 0) || (input->s_len == 0)) {
		return KOpenPGPEllipticTest_MissingTestVectorDefinitions;
	}
	if (input->curve == WEI25519) {
		int res = openpgp_libecc_eddsa_verify(input);
		if (res != KOpenPGPElliptic_OK) {
			return res;
		}
	} else {
		int res2 = openpgp_libecc_ecdsa_verify(input);
		if (res2 != KOpenPGPElliptic_OK) {
			return res2;
		}
	}
	return KOpenPGPEllipticTest_OK;
}

int openpgp_libecc_test_ecdsa_sign_and_verify_cycle(const ecdsa_params* input) {	
	if ((input == NULL) || (input->static_pubkey_len == 0) || (input->m_len == 0) || (input->r_len == 0) || (input->s_len == 0)) {
		return KOpenPGPEllipticTest_MissingTestVectorDefinitions;
	}
	ecdsa_result result;
	local_memset(&result, 0, sizeof(ecdsa_result));
	int resSign = KOpenPGPElliptic_OK;
	if (input->curve == WEI25519) {
		resSign = openpgp_libecc_eddsa_sign(&result, input);
	}
	else {
		if (input->nonce_len == 0) {
			// ECDSA test vector must come with a nonce.
			return KOpenPGPEllipticTest_MissingTestVectorDefinitions;;
		}
		resSign = openpgp_libecc_ecdsa_sign(&result, input);
	}
	if (resSign != KOpenPGPElliptic_OK) {
		return resSign;
	}
	/* The resulting R, S must be equal. */
	if (result.r_len != input->r_len) {
		return KOpenPGPEllipticTest_SignatureLengthMismatch;
	}
	if (result.s_len != input->s_len) {
		return KOpenPGPEllipticTest_SignatureLengthMismatch;
	}
	if (openpgp_libecc_memcmp(result.r, input->r, result.r_len) != 0) {
		return KOpenPGPEllipticTest_SignatureContentMismatch;
	}
	if (openpgp_libecc_memcmp(result.s, input->s, result.s_len) != 0) {
		return KOpenPGPEllipticTest_SignatureContentMismatch;
	}
	int resVerify = KOpenPGPElliptic_OK;
	if (input->curve == WEI25519) {
		resVerify = openpgp_libecc_eddsa_verify(input);
	}
	else {
		resVerify = openpgp_libecc_ecdsa_verify(input);
	}
	if (resVerify != KOpenPGPElliptic_OK) {
		return resVerify;
	}
	return KOpenPGPEllipticTest_OK;
}
