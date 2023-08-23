/*
 *  Copyright (C) 2023 - This file is part of libecc project
 *
 *  Authors:
 *      Marian Kechlibar <marian.kechlibar@circletech.net>
 *
 *  Contributors:
 *       Ryad BENADJILA <ryadbenadjila@gmail.com>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#ifndef __OPENPGP_LAYER_H__
#define __OPENPGP_LAYER_H__

#include "lib_ecc_config.h"
#include "lib_ecc_types.h"

#ifdef WITH_OPENPGP_LAYER
#include "openpgp_layer_constants.h"
#include "openpgp_layer_types.h"

 /**
  * This is a header file with definition of functions that enable the user to invoke libecc methods for OpenPGP-related functionality.
  * The standard used during implementation of this file was draft-ietf-openpgp-crypto-refresh-10 from June 2023, so not yet fully approved,
  * but close enough to the future standard. This layer will, in the future, be updated with further changes if necessary.
  *
  * OpenPGP treats its Elliptic Curve Cryptography in a remarkably non-uniform way and this file is intended to help the programmer use ECC functionality
  * with OpenPGP-compatible data without the need to convert the data structures from their original OpenPGP form.
  *
  * TL;DR: "take the data as you read them from the OpenPGP packets, convert them to the most basic const char* and invoke the function you need. You will
  * receive the output in the format needed by OpenPGP again."
  *
  * Important notice to developers: this header file, quite deliberately, avoids ALL the types declared in libecc's file words.h, such as u8. It only uses
  * the most standard C types and only includes "lib_ecc_config.h" which uses preprocessor definitions only, so it does not come in any contact with the
  * libecc's internal type system, and "lib_ecc_types.h", which only contain several enums. (Hopefully these enums' names' won't collide with yours.)
  *
  * This is motivated by the effort to make this file as fully compatible with other source bases as possible. Its inclusion anywhere else, be it C or C++ code,
  * shouldn't result in any type or definition conflicts.
  *
  * The corresponding C file obviously cannot be anywhere as neutral and actually includes libecc's headers and types, but you do not have to compile the C code
  * into your own PGP-related project, you can just use the header file for declarations and import the compiled library.
  *
  * You may also be interested in the openpgp_layer_constants.h file. As a general principle, functions declared here either return 0 on success (0 corresponds to
  * KOpenPGPElliptic_OK in the constants file), or a specific negative integer whose name explains the problem.
  * 
  * Note that in order to prevent confusion, the public and private keys are usually denoted either as "static" (the ones loaded from an OpenPGP key) or "ephemeral" 
  * (those generated for one operation only). 
  */

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * This function verifies an EdDSA signature (public key algorithm 0x22 in OpenPGP). EdDSA is intended to be deprecated in future versions of OpenPGP; AVOID GENERATING NEW KEYS with EdDSA as a signature algorithm.
	 * @param[in] signature_params The structure with necessary params. It must be non-NULL. The following params must be defined:
	 *                   static_pubkey, the public key from the signer's PGP key,
	 *				     m, the message whose signature is to be verified,
	 *                   r and s, the two components of the signature, their length must be 32,
	 *                   hash, the hash algorithm to be used.	 
	 * 
	 * All the other input parameters are ignored. Curve is expected to be WEI25519, but not checked.
	 */
	int openpgp_libecc_eddsa_verify(const ecdsa_params* signature_params);

	/**
	 * This function generates an EdDSA signature (public key algorithm 0x22). EdDSA is intended to be deprecated in future versions of OpenPGP; AVOID GENERATING NEW KEYS with EdDSA as a signature algorithm.
	 * 
	 * Description of parameters that differ from openpgp_libecc_eddsa_verify:
	 * @param[out] result The target structure which contains R and S in case of success. It must be non-NULL. Any previous values will be overwritten.
	 * @param[in] signature_params The structure with necessary params. It must be non-NULL. The following params must be defined:
	 *                   static_pubkey, the public key from the signer's PGP key,
	 *                   static_privkey, the private key from the signer's PGP key,
	 *				     m, the message to be signed,
	 *                   hash, the hash algorithm to be used.
	 * 
	 * All the other input parameters are ignored. Curve is expected to be WEI25519, but not checked.
	 */
	int openpgp_libecc_eddsa_sign(ecdsa_result* result, const ecdsa_params* signature_params);

	/**
	 * This function verifies an ECDSA signature (public key algorithm 0x19 in OpenPGP). Note that the name of the function differs only in one char from eddsa, but it has an extra parameter denoting the curve to be used.
	 *
	 * @param[in] signature_params The structure with necessary params. It must be non-NULL. The following params must be defined:
	 *                   static_pubkey, the public key from the signer's PGP key,
	 *				     m, the message whose signature is to be verified,
	 *                   r and s, the two components of the signature, their length must be 32,
	 *                   hash_alg, the hash algorithm to be used.
	 *					 curve, the curve to be used.
	 *
	 * Note: unlike in ECDH functions, legacy Ed25519 curve isn't supported by this function. For signatures and verifications using that curve, use the openpgp_libecc_eddsa_(sign|verify) functions.
	 */
	int openpgp_libecc_ecdsa_verify(const ecdsa_params* signature_params);

	/**
	 * This function generates an ECDSA signature (public key algorithm 0x19).
	 * The public and private keys must be in uncompressed affine format, e.g. 0x04 || x || y.
	 
	 * @param[out] result The target structure which contains R and S in case of success. It must be non-NULL. Any previous values will be overwritten.
	 * @param[in] signature_params The structure with necessary params. It must be non-NULL. The following params must be defined:
	 *                   static_pubkey, the public key from the signer's PGP key,
	 *                   static_privkey, the private key from the signer's PGP key,
	 *				     m, the message to be signed,
	 *                   hash, the hash algorithm to be used,
	 *					 curve, the curve to be used,
	 * The following parameter MAY be defined:
	 *					 nonce, the nonce to be used. If empty, the API will invoke its own PRNG to generate a nonce. The only situations when it makes sense to supply a nonce is when you either have a good cryptographic PRNG outside, or you want to run a test.
	 *
	 * Note: unlike in ECDH functions, legacy Ed25519 curve isn't supported by this function. For signatures and verifications using that curve, use the openpgp_libecc_eddsa_(sign|verify) functions.
	 */
	int openpgp_libecc_ecdsa_sign(ecdsa_result* result, const ecdsa_params* signature_params);

	/**
	 * This function generates a keypair and a shared secret to be used in ECDH. Used during encryption.
	 * 
	 * @param[out] target The target structure into which the results of the computation (the ephemeral key pair and the shared secret) will be stored. Alternatively, v and vG can be prefilled with desired values; in that case, only the shared secret will be computed.
	 * @param[in] dh_params The structure with necessary params. It must be non-NULL. The following params must be defined:
	 *                   static_pubkey, must be either in uncompressed affine format, e.g. 0x04 || x || y, for the regular curves, or 0x40 and 32 bytes for WEI25519
	 *					 curve, the curve to be used.
	 *
	 * This function can be used with both the regular curves and the legacy 25519 curve.
	 * 
	 * All the other input parameters are ignored.
	 */
	int openpgp_libecc_ecdh_generate_keypair_and_shared_secret(ecdh_result* target, const ecdh_params* dh_params);

	/**
	 * This function reconstructs the shared secret in ECDH. Used during decryption.
	 * 
	 * @param[out] target The target structure into which the shared secret will be stored. The ephemeral values aren't stored there during reconstruction (they are not needed).
	 * @param[in] dh_params The structure with necessary params. It must be non-NULL. The following params must be defined:
	 *                   ephemeral_pubkey ... the public key loaded from the PGP Public-Key Encrypted Session Key (PKESK) packet, must be either in uncompressed affine format, e.g. 0x04 || x || y, for the regular curves, or 0x40 and 32 bytes for WEI25519.
	 *                   static_privkey ... the private key loaded from the OpenPGP secret key of the recipient. 
	 *					 curve, the curve to be used.
	 * 
	 * This function can be used with both the regular curves and the legacy 25519 curve.
	 *
	 * All the other input parameters are ignored.
	 */
	int openpgp_libecc_ecdh_reconstruct_shared_secret(ecdh_result* target, const ecdh_params* dh_params);

	/**
	 * 
	 * This function is used to generate key pairs for OpenPGP key creation.
	 * @param[out] target The target structure into which the private key (v) and the public key (vG) will be stored. Shared secret will remain empty. So, in this particular case, v and vG play roles of static priv/pub keys of the future OpenPGP key, not the ephemeral ones.
	 * @param[in] curve The curve to use. SECP256R1, SECP384R1, SECP512R1 (the NIST curves) or BRAINPOOLP256R1, BRAINPOOLP384R1, BRAINPOOLP521R1 (the Brainpool curves). Legacy curves ARE NOT supported!
	 */
	int openpgp_libecc_generate_key_pair(ecdh_result* target, ec_curve_type curve);

	/**
	 * Compares two vectors of the same length, they must be non-NULL.
	 * Returns 0 if they are identical, -1 if the first differing byte is smaller in v1 than v2, 1 if greater.
	 * This is a non-optimized implementation.
	 */
	int openpgp_libecc_memcmp(const char* v1, const char* v2, int len);

	/**
	 * Returns the expected signature element length for a given curve (EdDSA / ECDSA signing).
	 */
	int openpgp_libecc_get_expected_signature_element_length(ec_curve_type aType);


#ifdef __cplusplus
}
#endif

#endif /* WITH_OPENPGP_LAYER */
#endif /* __OPENPGP_LAYER_H__ */
