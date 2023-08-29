#include "openpgp_layer.h"
#include <libecc/sig/eddsa.h>
#include <libecc/sig/ec_key.h>
#include <libecc/sig/sig_algs.h>
#include <libecc/sig/sig_algs_internal.h>
#include <libecc/curves/curves_list.h>
#include <libecc/curves/curves.h>
#include <libecc/sig/ecsdsa_common.h>
#include <libecc/sig/fuzzing_ecdsa.h>
#include <libecc/ecdh/ecccdh.h>
#include <libecc/ecdh/x25519_448.h>

#define EXTG(cond,val,lbl) do { if (cond) { ret = val; goto lbl ; } } while (0)

int openpgp_libecc_get_expected_signature_element_length(ec_curve_type aType) {
	switch (aType) {
	case WEI25519:
	case SECP256R1:
	case BRAINPOOLP256R1:
		return 32;
	case SECP384R1:
	case BRAINPOOLP384R1:
		return 48;
	case BRAINPOOLP512R1:
		return 64;
	case SECP521R1:
		return 66;
	default:
		return 0;
	}
}

int openpgp_libecc_eddsa_verify(const ecdsa_params* signature_params) {
	int ret = KOpenPGPElliptic_OK;
	ec_params params;
	const ec_str_params* str_params = NULL;
	ec_pub_key pub_key;
	char signature[OPENPGP_LAYER_MAX_KEY_SIZE];
	/* Local variables for readability. */
	const char* r		= (signature_params ? signature_params->r : NULL);
	int   r_len = (signature_params ? signature_params->r_len : 0);
	const char* s		= (signature_params ? signature_params->s : NULL);
	int   s_len = (signature_params ? signature_params->s_len : 0);
	const char* m = (signature_params ? signature_params->m : NULL);
	int   m_len = (signature_params ? signature_params->m_len : 0);
	const char* static_pubkey = (signature_params ? signature_params->static_pubkey : NULL);
	int   static_pubkey_len = (signature_params ? signature_params->static_pubkey_len : 0);
	hash_alg_type hash_alg = (signature_params ? signature_params->hash : UNKNOWN_HASH_ALG);
	/* Basic sanity checks. */
	ret = (sizeof(char) - sizeof(u8)); EXTG(ret, KOpenPGPElliptic_IncorrectDataType, err);
	ret = ((r == NULL) || (r_len == 0) || (s == NULL) || (s_len == 0) || (static_pubkey == NULL) || (static_pubkey_len == 0)); EXTG(ret, KOpenPGPElliptic_CurveIllegalNullParameter, err);
	ret = (static_pubkey[0] - KOpenPGPElliptic_NativeFormatIndicator); EXTG(ret, KOpenPGPElliptic_NotAEdDSASignature, err);
	ret = (static_pubkey_len != (1 + EDDSA25519_PUB_KEY_ENCODED_LEN)); EXTG(ret, KOpenPGPElliptic_EdDSAPubKeyLengthMismatch, err);
	ret = (r_len != EDDSA25519_PUB_KEY_ENCODED_LEN) || (s_len != EDDSA25519_PUB_KEY_ENCODED_LEN); EXTG(ret, KOpenPGPElliptic_CurveIncorrectSignatureLength, err);
	/* OK, the entries are sane, we can actually attempt to verify the signature. */
	ret = ec_get_curve_params_by_type(WEI25519, &str_params); EXTG(ret, KOpenPGPElliptic_CurveDefinitionNotFound, err);
	ret = import_params(&params, str_params); EXTG(ret, KOpenPGPElliptic_CurveLoadingFailed, err);
	/* skipping the 0x40 header byte */
	ret = eddsa_import_pub_key(&pub_key, (const u8*)static_pubkey + 1, (u16)static_pubkey_len - 1, &params, EDDSA25519); EXTG(ret, KOpenPGPElliptic_CurvePubKeyInitFailed, err);
	local_memcpy(signature, r, r_len);
	local_memcpy(signature + r_len, s, s_len);
	ret = generic_ec_verify((const u8*)signature, r_len + s_len, &pub_key, (const u8*)m, m_len, EDDSA25519, hash_alg, NULL, 0); EXTG(ret, KOpenPGPElliptic_CurveVerifySignatureFailed, err);
err:
	local_memset(&pub_key, 0, sizeof(pub_key));
	return ret;
}

int openpgp_libecc_eddsa_sign(ecdsa_result* result, const ecdsa_params* signature_params) {
	int ret = KOpenPGPElliptic_OK;
	ec_params params;
	const ec_str_params* str_params = NULL;
	int expected_sig_length = 0;
	ec_key_pair key_pair;	
	char signature[OPENPGP_LAYER_MAX_KEY_SIZE];
	const char* m = (signature_params ? signature_params->m : NULL);
	int   m_len = (signature_params ? signature_params->m_len : 0);
	const char* static_pubkey = (signature_params ? signature_params->static_pubkey : NULL);
	int   static_pubkey_len = (signature_params ? signature_params->static_pubkey_len : 0);
	const char* static_privkey = (signature_params ? signature_params->static_privkey : NULL);
	int   static_privkey_len = (signature_params ? signature_params->static_privkey_len : 0);
	/* Basic sanity checks. */
	ret = (sizeof(char) - sizeof(u8)); EXTG(ret, KOpenPGPElliptic_IncorrectDataType, err);
	ret = ((result == NULL) || (static_privkey == NULL) || (static_privkey_len == 0) || (static_pubkey == NULL) || (static_pubkey_len == 0)); EXTG(ret, KOpenPGPElliptic_CurveIllegalNullParameter, err);
	ret = (static_pubkey[0] - KOpenPGPElliptic_NativeFormatIndicator); EXTG(ret, KOpenPGPElliptic_NotAEdDSASignature, err);
	ret = (static_pubkey_len != (1 + EDDSA25519_PUB_KEY_ENCODED_LEN)); EXTG(ret, KOpenPGPElliptic_EdDSAPubKeyLengthMismatch, err);
	ret = (static_privkey_len != EDDSA25519_PUB_KEY_ENCODED_LEN); EXTG(ret, KOpenPGPElliptic_EdDSAPrivKeyLengthMismatch, err);
	expected_sig_length = openpgp_libecc_get_expected_signature_element_length(WEI25519) * 2;	
	ret = (OPENPGP_LAYER_MAX_KEY_SIZE < expected_sig_length); EXTG(ret, KOpenPGPElliptic_CurveTargetBufferTooShort, err);
	local_memset(result, 0, sizeof(ecdsa_result));
	/* OK, the entries are sane, we can actually attempt to sign the data the signature. */
	ret = ec_get_curve_params_by_type(WEI25519, &str_params); EXTG(ret, KOpenPGPElliptic_CurveDefinitionNotFound, err);
	ret = import_params(&params, str_params); EXTG(ret, KOpenPGPElliptic_CurveLoadingFailed, err);
	/* skipping the 0x40 header byte */
	ret = eddsa_import_pub_key(&key_pair.pub_key, (const u8*)static_pubkey + 1, (u16)static_pubkey_len - 1, &params, EDDSA25519); EXTG(ret, KOpenPGPElliptic_CurvePubKeyInitFailed, err);
	ret = eddsa_import_priv_key(&key_pair.priv_key, (const u8*)static_privkey, static_privkey_len, &params, EDDSA25519); EXTG(ret, KOpenPGPElliptic_CurvePrivKeyInitFailed, err);
	ret = _eddsa_sign((u8*)signature, (u8)expected_sig_length, &key_pair, (const u8*)m, (u32)m_len, NULL, EDDSA25519, SHA512, NULL, 0); EXTG(ret, KOpenPGPElliptic_CurveCreateSignatureFailed, err);
	local_memcpy(result->r, signature, expected_sig_length / 2);
	result->r_len = expected_sig_length / 2;
	local_memcpy(result->s, signature + (expected_sig_length / 2), expected_sig_length / 2);
	result->s_len = expected_sig_length / 2;
err:
	local_memset(&key_pair, 0, sizeof(key_pair));
	return ret;
}

int openpgp_libecc_ecdsa_verify(const ecdsa_params* signature_params) {
	int ret = KOpenPGPElliptic_OK;
	ec_params params;
	const ec_str_params* str_params = NULL;
	ec_pub_key pub_key;
	char signature[320];
	struct ec_verify_context ctx;
	/* Local variables for readability. */
	const char* r = (signature_params ? signature_params->r : NULL);
	int   r_len = (signature_params ? signature_params->r_len : 0);
	const char* s = (signature_params ? signature_params->s : NULL);
	int   s_len = (signature_params ? signature_params->s_len : 0);
	const char* m = (signature_params ? signature_params->m : NULL);
	int   m_len = (signature_params ? signature_params->m_len : 0);
	const char* static_pubkey = (signature_params ? signature_params->static_pubkey : NULL);
	int   static_pubkey_len = (signature_params ? signature_params->static_pubkey_len : 0);
	hash_alg_type hash_alg = (signature_params ? signature_params->hash : UNKNOWN_HASH_ALG);
	ec_curve_type curve = (signature_params ? signature_params->curve : UNKNOWN_CURVE);
	local_memset(signature, 0, OPENPGP_LAYER_MAX_KEY_SIZE);
	/* Basic sanity checks. */	
	ret = (sizeof(char) - sizeof(u8)); EXTG(ret, KOpenPGPElliptic_IncorrectDataType, err);
	ret = ((r == NULL) || (r_len == 0) || (s == NULL) || (s_len == 0) || (static_pubkey == NULL) || (static_pubkey_len == 0)); EXTG(ret, KOpenPGPElliptic_CurveIllegalNullParameter, err);
	ret = (static_pubkey[0] - KOpenPGPElliptic_UncompressedPointIndicator); EXTG(ret, KOpenPGPElliptic_CurveMalformedPoint, err);
	ret = (static_pubkey_len != (2 * openpgp_libecc_get_expected_signature_element_length(curve) + 1)); EXTG(ret, KOpenPGPElliptic_CurveMalformedPoint, err);
	ret = (r_len != openpgp_libecc_get_expected_signature_element_length(curve)); EXTG(ret, KOpenPGPElliptic_CurveIncorrectSignatureLength, err);
	ret = (s_len != openpgp_libecc_get_expected_signature_element_length(curve)); EXTG(ret, KOpenPGPElliptic_CurveIncorrectSignatureLength, err);
	/* OK, the entries are sane, we can actually attempt to verify the signature. */
	ret = ec_get_curve_params_by_type(curve, &str_params); EXTG(ret, KOpenPGPElliptic_CurveDefinitionNotFound, err);
	ret = import_params(&params, str_params); EXTG(ret, KOpenPGPElliptic_CurveLoadingFailed, err);
	ret = ec_pub_key_import_from_aff_buf(&pub_key, &params, (const u8*)static_pubkey + 1, (u8)static_pubkey_len - 1, ECDSA); EXTG(ret, KOpenPGPElliptic_CurvePubKeyInitFailed, err);
	local_memcpy(signature, r, r_len);
	local_memcpy(signature + r_len, s, s_len);
	ret = ec_verify_init(&ctx, &pub_key, (const u8*)signature, r_len + s_len, ECDSA, hash_alg, NULL, 0); EXTG(ret, KOpenPGPElliptic_CurveVerificationContextInitFailed, err);
	ret = ecdsa_verify_raw(&ctx, (const u8*)m, (u8)m_len); EXTG(ret, KOpenPGPElliptic_CurveVerifySignatureFailed, err);
err:
	local_memset(&ctx, 0, sizeof(ctx));
	local_memset(&pub_key, 0, sizeof(pub_key));
	return ret;
}

int openpgp_libecc_ecdsa_sign(ecdsa_result* result, const ecdsa_params* signature_params) {
	int ret = KOpenPGPElliptic_OK;
	int expected_sig_length = 0;
	ec_params params;
	const ec_str_params* str_params = NULL;
	ec_key_pair key_pair;
	struct ec_sign_context ctx;
	char signature[OPENPGP_LAYER_MAX_KEY_SIZE];
	/* Local variables for readability. */
	const char* m = (signature_params ? signature_params->m : NULL);
	int   m_len = (signature_params ? signature_params->m_len : 0);
	const char* static_pubkey = (signature_params ? signature_params->static_pubkey : NULL);
	int   static_pubkey_len = (signature_params ? signature_params->static_pubkey_len : 0);
	const char* static_privkey = (signature_params ? signature_params->static_privkey : NULL);
	int   static_privkey_len = (signature_params ? signature_params->static_privkey_len : 0);
	const char* nonce =   (signature_params && signature_params->nonce_len ? signature_params->nonce : NULL);
	int   nonce_len = (signature_params && signature_params->nonce_len ? signature_params->nonce_len : 0);
	hash_alg_type hash_alg = (signature_params ? signature_params->hash : UNKNOWN_HASH_ALG);
	ec_curve_type curve = (signature_params ? signature_params->curve : UNKNOWN_CURVE);
	local_memset(signature, 0, OPENPGP_LAYER_MAX_KEY_SIZE);
	/* Basic sanity checks. */
	ret = (sizeof(char) - sizeof(u8)); EXTG(ret, KOpenPGPElliptic_IncorrectDataType, err);
	ret = ((result == NULL) || (static_privkey == NULL) || (static_privkey_len == 0) || (static_pubkey == NULL) || (static_pubkey_len == 0)); EXTG(ret, KOpenPGPElliptic_CurveIllegalNullParameter, err);
	ret = (static_pubkey[0] - KOpenPGPElliptic_UncompressedPointIndicator); EXTG(ret, KOpenPGPElliptic_CurveMalformedPoint, err);
	expected_sig_length = openpgp_libecc_get_expected_signature_element_length(curve) * 2;	
	ret = (OPENPGP_LAYER_MAX_KEY_SIZE < expected_sig_length); EXTG(ret, KOpenPGPElliptic_CurveTargetBufferTooShort, err);
	local_memset(result, 0, sizeof(ecdsa_result));
	ret = (static_pubkey_len != (2 * openpgp_libecc_get_expected_signature_element_length(curve) + 1)); EXTG(ret, KOpenPGPElliptic_CurveMalformedPoint, err);
	ret = (static_privkey_len != openpgp_libecc_get_expected_signature_element_length(curve)); EXTG(ret, KOpenPGPElliptic_CurveMalformedPoint, err);
	/* OK, the entries are sane, we can actually attempt to create the signature. */
	ret = ec_get_curve_params_by_type(curve, &str_params); EXTG(ret, KOpenPGPElliptic_CurveDefinitionNotFound, err);
	ret = import_params(&params, str_params); EXTG(ret, KOpenPGPElliptic_CurveLoadingFailed, err);
	ret = ec_key_pair_import_from_priv_key_buf(&key_pair, &params, (const u8*)static_privkey, static_privkey_len, ECDSA); EXTG(ret, KOpenPGPElliptic_CurvePrivKeyInitFailed, err);
	ret = ec_sign_init(&ctx, &key_pair, ECDSA, hash_alg, NULL, 0); EXTG(ret, KOpenPGPElliptic_CurveSignContextInitFailed, err);
	ret = ecdsa_sign_raw(&ctx, (const u8*)m, (u8)m_len, (u8*)signature, (u8)expected_sig_length, (const u8*) nonce, (u8) nonce_len); EXTG(ret, KOpenPGPElliptic_CurveCreateSignatureFailed, err);
	local_memcpy(result->r, signature, expected_sig_length / 2);
	result->r_len = expected_sig_length / 2;
	local_memcpy(result->s, signature + (expected_sig_length / 2), expected_sig_length / 2);
	result->s_len = expected_sig_length / 2;
err:
	local_memset(&key_pair, 0, sizeof(key_pair));
	local_memset(&ctx, 0, sizeof(ctx));
	return ret;
}

int format_into_ecdh_result(ecdh_result* target, ec_curve_type curve, const ec_key_pair* key_pair, int expected_unc_point_len, int expected_ss_len, ec_params* shortw_curve_params) {
	int ret = KOpenPGPElliptic_OK;
	/* Unused shortw_curve_params parameter */
	(void)shortw_curve_params;
	if (curve != WEI25519) {
		// wlen ... len in words
		int expected_priv_len = openpgp_libecc_get_expected_signature_element_length(curve);
		ret = nn_export_to_buf((u8*)target->ephemeral_privkey, expected_priv_len, &key_pair->priv_key.x);  EXTG(ret, KOpenPGPElliptic_CurveExportFailed, err);
		target->ephemeral_privkey_len = expected_priv_len;
		target->ephemeral_pubkey[0] = KOpenPGPElliptic_UncompressedPointIndicator; // Indicates uncompressed point
		ret = prj_pt_export_to_aff_buf(&key_pair->pub_key.y, (u8*)target->ephemeral_pubkey + 1, expected_unc_point_len); EXTG(ret, KOpenPGPElliptic_CurveExportFailed, err);
		target->ephemeral_pubkey_len = expected_unc_point_len + 1;
		target->shared_secret_len = expected_ss_len;
	}
	else {
		ret = KOpenPGPElliptic_Legacy25519ECDHNotSupportedYet;
	}
err:
	return ret;
}

int openpgp_libecc_ecdh_generate_keypair_and_shared_secret(ecdh_result* target, const ecdh_params* dh_params) {
	int ret = KOpenPGPElliptic_OK;
	ec_params params;
	const ec_str_params* str_params = NULL;
	ec_key_pair key_pair;			
	/* Local variables for readability. */
	const char* static_pubkey = (dh_params ? dh_params->static_pubkey : NULL);
	int   static_pubkey_len = (dh_params ? dh_params->static_pubkey_len : 0);
	ec_curve_type curve = (dh_params ? dh_params->curve : UNKNOWN_CURVE);
	int exp_el_len = openpgp_libecc_get_expected_signature_element_length(curve);
	/* Basic sanity checks. */
	ret = (sizeof(char) - sizeof(u8)); EXTG(ret, KOpenPGPElliptic_IncorrectDataType, err);
	ret = ((target == NULL) || (static_pubkey == NULL) || (static_pubkey_len == 0)); EXTG(ret, KOpenPGPElliptic_CurveIllegalNullParameter, err);
	if (curve == WEI25519) {
		u8 priv_scalar[X25519_SIZE] = { 0 };
		ret = (static_pubkey_len - (X25519_SIZE + 1)); EXTG(ret, KOpenPGPElliptic_CurveMalformedPoint, err);
		if (target->ephemeral_privkey_len != 0) {
			// Read ephemeral keys from target; this is the case of test vectors. 
			local_memcpy(priv_scalar, target->ephemeral_privkey, X25519_SIZE); EXTG(ret, KOpenPGPElliptic_EphemeralPrivateKeyLoadingFailed, err2);
		}
		else {
			// Generate a new ephemeral key pair; this is the case of normal usage.
			local_memset(target, 0, sizeof(ecdh_result));
			ret = x25519_gen_priv_key(priv_scalar); EXTG(ret, KOpenPGPElliptic_CurveSecretGenerationFailed, err2);
		}
		target->shared_secret_len = X25519_SIZE;
		target->ephemeral_pubkey_len = X25519_SIZE + 1;
		target->ephemeral_pubkey[0] = KOpenPGPElliptic_NativeFormatIndicator;
		ret = x25519_init_pub_key(priv_scalar, (u8*)&(target->ephemeral_pubkey[1])); EXTG(ret, KOpenPGPElliptic_CurveSecretGenerationFailed, err2);
		ret = x25519_derive_secret(priv_scalar, (const u8*)&static_pubkey[1], (u8*)target->shared_secret); EXTG(ret, KOpenPGPElliptic_CurveSecretGenerationFailed, err2);
	err2:
		local_memset(priv_scalar, 0, X25519_SIZE);
	}
	else {		
		/* Further sanity checks. The static pubkey must be in the 0x04 || X || Y format. */
		ret = (static_pubkey_len - (2 * exp_el_len + 1)); EXTG(ret, KOpenPGPElliptic_CurveMalformedPoint, err);
		ret = (static_pubkey[0] - KOpenPGPElliptic_UncompressedPointIndicator); EXTG(ret, KOpenPGPElliptic_CurveMalformedPoint, err);
		ret = ec_get_curve_params_by_type(curve, &str_params); EXTG(ret, KOpenPGPElliptic_CurveDefinitionNotFound, err);
		ret = import_params(&params, str_params); EXTG(ret, KOpenPGPElliptic_CurveLoadingFailed, err);
		/* Here should be an if/else, prefilling the keypair from the ecdh_result for testing. */
		if (target->ephemeral_privkey_len != 0) {
			// Read ephemeral keys from target; this is the case of test vectors.
			ret = ecccdh_import_key_pair_from_priv_key_buf(&key_pair, &params, (const u8*)target->ephemeral_privkey, (u8)target->ephemeral_privkey_len); EXTG(ret, KOpenPGPElliptic_EphemeralPrivateKeyLoadingFailed, err);
		}
		else {
			local_memset(target, 0, sizeof(ecdh_result));
			ret = ecccdh_gen_key_pair(&key_pair, &params); EXTG(ret, KOpenPGPElliptic_CurveKeyPairGenerationFailed, err);
		}
		ret = ecccdh_derive_secret(&key_pair.priv_key, (const u8*) static_pubkey + 1, static_pubkey_len - 1, (u8*)target->shared_secret, exp_el_len); EXTG(ret, KOpenPGPElliptic_CurveSecretGenerationFailed, err);
		ret = format_into_ecdh_result(target, curve, &key_pair, 2*exp_el_len, exp_el_len, &params);
	}
err:
	local_memset(&key_pair, 0, sizeof(key_pair));
	if (ret != KOpenPGPElliptic_OK) {
		local_memset(target, 0, sizeof(ecdh_result));
	}	
	/*
	// NOTE: for debug purpose 
	buf_print("(Deriv) Pubkey:		", static_pubkey, static_pubkey_len);
	buf_print("(Deriv) Target->v:   ", target->v, target->vLength);
	buf_print("(Deriv) Target->vG:  ", target->vG, target->vGLength);
	buf_print("(Deriv) Target->ss:  ", target->sharedSecret, target->sharedSecretLength);		
	*/
	return ret;
}

int openpgp_libecc_ecdh_reconstruct_shared_secret(ecdh_result* target, const ecdh_params* dh_params) {
	int ret = KOpenPGPElliptic_OK;
	ec_params params;
	const ec_str_params* str_params = NULL;
	ec_key_pair key_pair;
	/* Local variables for readability. */
	const char* ephemeral_pubkey = (dh_params ? dh_params->ephemeral_pubkey : NULL);
	int   ephemeral_pubkey_len = (dh_params ? dh_params->ephemeral_pubkey_len : 0);
	const char* static_privkey = (dh_params ? dh_params->static_privkey : NULL);
	int   static_privkey_len = (dh_params ? dh_params->static_privkey_len : 0);
	ec_curve_type curve = (dh_params ? dh_params->curve : UNKNOWN_CURVE);
	int exp_el_len = openpgp_libecc_get_expected_signature_element_length(curve);
	/* Basic sanity checks. */
	ret = (sizeof(char) - sizeof(u8)); EXTG(ret, KOpenPGPElliptic_IncorrectDataType, err);
	ret = ((target == NULL) || (ephemeral_pubkey == NULL) || (ephemeral_pubkey_len == 0) || (static_privkey == NULL) || (static_privkey_len == 0)); EXTG(ret, KOpenPGPElliptic_CurveIllegalNullParameter, err);
	local_memset(target, 0, sizeof(ecdh_result));
	if (curve == WEI25519) {
		unsigned int i;
		u8 scalar[X25519_SIZE] = { 0 };
		/* Sanity checks */
		ret = (static_privkey_len - X25519_SIZE); EXTG(ret, KOpenPGPElliptic_IncorrectDataType, err2);
		ret = (ephemeral_pubkey_len - (X25519_SIZE + 1)); EXTG(ret, KOpenPGPElliptic_IncorrectDataType, err2);
		/* Reverse the endianness as OpenPGP stores little endian */
		for (i = 0; i < X25519_SIZE; i++) {
			scalar[i] = static_privkey[X25519_SIZE - i - 1];
		}
		ret = x25519_derive_secret(scalar, (const u8*)&ephemeral_pubkey[1], (u8*)target->shared_secret); EXTG(ret, KOpenPGPElliptic_CurveSecretGenerationFailed, err2);
		target->shared_secret_len = X25519_SIZE;
	err2:	
		local_memset(scalar, 0, X25519_SIZE);
	}
	else {
		/* Further sanity checks. The ephemeral pubkey must be in the 0x04 || X || Y format. */
		ret = (ephemeral_pubkey_len - (2 * exp_el_len + 1)); EXTG(ret, KOpenPGPElliptic_CurveMalformedPoint, err);
		ret = (ephemeral_pubkey[0] - KOpenPGPElliptic_UncompressedPointIndicator); EXTG(ret, KOpenPGPElliptic_CurveMalformedPoint, err);
		ret = ec_get_curve_params_by_type(curve, &str_params); EXTG(ret, KOpenPGPElliptic_CurveDefinitionNotFound, err);
		ret = import_params(&params, str_params); EXTG(ret, KOpenPGPElliptic_CurveLoadingFailed, err);
		ret = ecccdh_import_key_pair_from_priv_key_buf(&key_pair, &params, (const u8*)static_privkey, static_privkey_len); EXTG(ret, KOpenPGPElliptic_CurvePrivKeyInitFailed, err);
		ret = ecccdh_derive_secret(&key_pair.priv_key, (const u8*) ephemeral_pubkey + 1, ephemeral_pubkey_len - 1, (u8*)target->shared_secret, exp_el_len);  EXTG(ret, KOpenPGPElliptic_CurveSecretGenerationFailed, err);
		target->shared_secret_len = exp_el_len;
	}	
err:
	local_memset(&key_pair, 0, sizeof(key_pair));
	if (ret != KOpenPGPElliptic_OK) {
		local_memset(target, 0, sizeof(ecdh_result));
	}	
	/*
	// NOTE: for debug purpose 
	buf_print("(Rec) Pubkey:		", ephemeral_pubkey, ephemeral_pubkey_len);
	buf_print("(Rec) Privkey:		", static_privkey, static_privkey_len);
	buf_print("(Rec) Target->v:   ", target->v, target->vLength);
	buf_print("(Rec) Target->vG:  ", target->vG, target->vGLength);
	buf_print("(Rec) Target->ss:  ", target->sharedSecret, target->sharedSecretLength);		
	*/
	return ret;
}

int openpgp_libecc_generate_key_pair(ecdh_result* target, ec_curve_type curve) {
	int ret = KOpenPGPElliptic_OK;
	ec_params params;
	const ec_str_params* str_params = NULL;
	ec_key_pair key_pair;
	/* Basic sanity checks. */
	ret = (sizeof(char) - sizeof(u8)); EXTG(ret, KOpenPGPElliptic_IncorrectDataType, err);
	ret = (target == NULL); EXTG(ret, KOpenPGPElliptic_CurveIllegalNullParameter, err);
	switch (curve) {
	case SECP256R1:
	case SECP384R1:
	case SECP521R1:
	case BRAINPOOLP256R1:
	case BRAINPOOLP384R1:
	case BRAINPOOLP512R1:
		break;
	default:
		ret = KOpenPGPElliptic_CurveUnsupported; EXTG(ret, KOpenPGPElliptic_CurveUnsupported, err);
		break;
	}
	ret = ec_get_curve_params_by_type(curve, &str_params); EXTG(ret, KOpenPGPElliptic_CurveDefinitionNotFound, err);
	ret = import_params(&params, str_params); EXTG(ret, KOpenPGPElliptic_CurveLoadingFailed, err);
	local_memset(target, 0, sizeof(ecdh_result));
	ret = ecccdh_gen_key_pair(&key_pair, &params); EXTG(ret, KOpenPGPElliptic_CurveKeyPairGenerationFailed, err);
	ret = format_into_ecdh_result(target, curve, &key_pair, 2 * openpgp_libecc_get_expected_signature_element_length(curve), 0, &params);
err:
	local_memset(&key_pair, 0, sizeof(ec_key_pair));
	if (ret != KOpenPGPElliptic_OK) {
		local_memset(target, 0, sizeof(ecdh_result));
	}	
	return ret;

}

int openpgp_libecc_memcmp(const char* v1, const char* v2, int len) {
	int i;
	for (i = 0; i < len; i++) {
		if (v1[i] < v2[i]) {
			return -1;
		}
		else if (v1[i] > v2[i]) {
			return 1;
		}
	}
	return 0;
}
