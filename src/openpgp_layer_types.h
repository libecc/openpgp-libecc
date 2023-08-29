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
#ifndef __OPENPGP_LAYER_TYPES_H__
#define __OPENPGP_LAYER_TYPES_H__

#include <libecc/lib_ecc_config.h>
#include <libecc/lib_ecc_types.h>

/**
 * Good understanding of those types is necessary for successful use of the library. 
 * A parameter is considered undefined if its length is 0.
 * 
 * Usually, only a subset of all the parameters contained within the structs needs to be defined in order to run an ECC operation. Comments around individual functions specify which ones. 
 * The structs are intended to be set to all zeros first:
 * 
 * ecdh_params params;
 * memset(&params, 0, sizeof(ecdh_params));
 * 
 * This has the effects of undefining all the parameters at once and making sure that no rubbish from the stack gets treated as legitimate values.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define OPENPGP_LAYER_MAX_KEY_SIZE 256

/**
 * This struct must be populated for ECDH operations: construction and reconstruction of the shared secret.
 */
typedef struct {
    /* The static public key (the one from an OpenPGP public key of the sender). */
    char static_pubkey[OPENPGP_LAYER_MAX_KEY_SIZE];
    /* The actual length of the static public key in octets. Must be equal to 2*get_expected_signature_element_length(curve) + 1 for regular curves, or 33 bytes for WEI25519, is checked. */
    int  static_pubkey_len;
    /* The static private key (the one from an OpenPGP secret key of the recipient). */
    char static_privkey[OPENPGP_LAYER_MAX_KEY_SIZE];
    /* The actual length of the static private key in octets. */
    int  static_privkey_len;
    /* The ephemeral public key, loaded from the PGP Public-Key Encrypted Session Key (PKESK) packet, must be either in uncompressed affine format, e.g. 0x04 || x || y, for the regular curves, or 0x40 and 32 bytes for WEI25519. */
    char ephemeral_pubkey[OPENPGP_LAYER_MAX_KEY_SIZE];
    /* The actual length of the ephemeral public key in octets. If defined, must be equal to 2*get_expected_signature_element_length(curve) + 1 for regular curves, or 33 bytes for WEI25519, is checked. */
    int  ephemeral_pubkey_len;
    /* The curve type used for computation. */
    ec_curve_type curve;
} ecdh_params;

/**
 * In this struct, results of an ECDH operation are returned, IF the operation ran correctly (no error code returned).
 */
typedef struct {
    /* The ephemeral private key. Won't be sent anywhere, is only used in tests. */
    char ephemeral_privkey[OPENPGP_LAYER_MAX_KEY_SIZE];
    /* The actual length of the ephemeral private key in octets. */
    int  ephemeral_privkey_len;
    /* The ephemeral public key, serialized into a format ready for a PGP Public-Key Encrypted Session Key (PKESK) packet. */
    char ephemeral_pubkey[OPENPGP_LAYER_MAX_KEY_SIZE];    
    /* The actual length of the ephemeral public key in octets. */
    int  ephemeral_pubkey_len;
    /* The resulting shared secret. Won't be sent anywhere, but will be used in the KDF that produces the wrapping key for AESKeyWrap. */
    char shared_secret[OPENPGP_LAYER_MAX_KEY_SIZE];
    /* The actual length of the shared secret in octets. */
    int  shared_secret_len;
} ecdh_result;

/**
 * This struct must be populated for ECDSA and EdDSA operations: signature generation and verification.
 */
typedef struct {
    /* The static public key (the one from an OpenPGP public key of the signer). */
    char static_pubkey[OPENPGP_LAYER_MAX_KEY_SIZE];
    /* The actual length of the static public key in octets. Must be equal to 2*get_expected_signature_element_length(curve) + 1 for regular curves, or 33 bytes for WEI25519, is checked. */
    int  static_pubkey_len;
    /* The static private key (the one from an OpenPGP secret key of the signer). */
    char static_privkey[OPENPGP_LAYER_MAX_KEY_SIZE];
    /* The actual length of the static private key in octets. */
    int  static_privkey_len;
    /* The hash of the signed part of the OpenPGP message (note that in EdDSA, the message is hashed, then the hash serves as an input into the EdDSA signing algorithm, where it is hashed again) */
    char m[OPENPGP_LAYER_MAX_KEY_SIZE];
    /* The actual length of the hash in octets.*/
    int m_len;
    /* If defined, in ECDSA (not EdDSA), this random nonce will be used for computation of the signature. (It is never used during verification.) Otherwise, the API will run its own PRNG to generate a nonce.
       ONLY SPECIFY A NONCE IF YOU HAVE A GOOD PRNG OR IF YOU ARE RUNNING A UNIT TEST WITH PREDEFINED VALUES. Strong nonces are essential for security. */
    char nonce[OPENPGP_LAYER_MAX_KEY_SIZE];
    /* The actual length of the nonce in octets. If 0, the API will generate a new nonce. */
    int  nonce_len;
    /* The value of R, used in verification only. For signing, R will be returned in ecdsa_result. */
    char r[OPENPGP_LAYER_MAX_KEY_SIZE];
    /* The actual length of r in octets. */
    int  r_len;
    /* The value of S, used in verification only. For signing, S will be returned in ecdsa_result. */
    char s[OPENPGP_LAYER_MAX_KEY_SIZE];
    /* The actual length of r in octets. */
    int  s_len;
    /* The curve type used for computation. For EdDSA, WEI25519. */
    ec_curve_type curve;
    /* The hash algorithm to be used in ECDSA or EdDSA proper. You can read the hash algorithm from the signature packet (see 9.5. Hash Algorithms of OpenPGP spec), but you need to convert it to libecc's hash_alg_type first. So, for example, openPGP's value "10", which is SHA512, translates to 4 (SHA512) from the libecc's enum.*/
    hash_alg_type hash;
} ecdsa_params;

/**
 * In this struct, results of an ECDSA / EdDSA operation are returned, IF the operation ran correctly (no error code returned).
 */
typedef struct {
    /* The value of R. */
    char r[OPENPGP_LAYER_MAX_KEY_SIZE];
    /* The actual length of r in octets. */
    int  r_len;
    /* The value of S. */
    char s[OPENPGP_LAYER_MAX_KEY_SIZE];
    /* The actual length of r in octets. */
    int  s_len;
} ecdsa_result;

/**
 * A combined struct used for running tests of ECDH.
 */
typedef struct {
    const ecdh_params     *input;
    const ecdh_result     *expected_result;
} ecdh_test_value;

#ifdef __cplusplus
}
#endif


#endif // __OPENPGP_LAYER_TYPES_H__
