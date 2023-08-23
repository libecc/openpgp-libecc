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
#ifndef __OPENPGP_LAYER_CONSTANTS_H__
#define __OPENPGP_LAYER_CONSTANTS_H__

enum OpenPGPErrors {
/* Returned in case of success. */
	KOpenPGPElliptic_OK = 0,

/* Returned if sizeof(char) != sizeof(u8). Should not normally happen, only on weird architectures. */
	KOpenPGPElliptic_IncorrectDataType = -213400,

/* Returned from Elliptic_EdDSACheck if the beginning octet of aQ isn't 0x40 (header), which means that the supplied EC point isn't in the native format for EdDSA. */
	KOpenPGPElliptic_NotAEdDSASignature = -213401,

/* Returned from Elliptic_EdDSACheck if the length of aQ minus the beginning header octet differs from 32. */
	KOpenPGPElliptic_EdDSAPubKeyLengthMismatch = -213402,

/* Returned if the necessary curve definition wasn't found. This may be caused by a restrictive setting in lib_ecc_config.h. */
	KOpenPGPElliptic_CurveDefinitionNotFound = -213403,

/* Returned if loading of the curve definition into a working structure failed. This shouldn't normally happen at all. */
	KOpenPGPElliptic_CurveLoadingFailed = -213404,

/* Returned if loading of the public key into the EC failed. Indicates a format problem with the input value. */
	KOpenPGPElliptic_CurvePubKeyInitFailed = -213405,

/* Returned if loading of the private key into the EC failed. Indicates a format problem with one of the input values. */
	KOpenPGPElliptic_CurvePrivKeyInitFailed = -213406,

/* Returned if verification of signature failed. */
	KOpenPGPElliptic_CurveVerifySignatureFailed = -213407,

/* Returned if signature size differs from expected size. */
	KOpenPGPElliptic_CurveIncorrectSignatureLength = -213408,

/* Returned from Elliptic_EdDSASign if private key length does not correspond to standard. */
	KOpenPGPElliptic_EdDSAPrivKeyLengthMismatch = -213409,

/* Returned if creation of signature failed. */
	KOpenPGPElliptic_CurveCreateSignatureFailed = -213410,

/* Returned if pointer to TEllipticDHKeyPair was NULL. */
	KOpenPGPElliptic_CurveIllegalNullParameter = -213411,

/* Returned if call to ecccdh_gen_key_pair failed. */
	KOpenPGPElliptic_CurveKeyPairGenerationFailed = -213412,

/* Returned if call to point uncompression failed. */
	KOpenPGPElliptic_CurveKeyPointDecompressionFailed = -213412,

/* Returned if any point provided to ECDH operations could not be processed (decompressed etc.) */
	KOpenPGPElliptic_CurvePointCouldNotBeProcessed = -213413,

/* Returned if secret generation failed. */
	KOpenPGPElliptic_CurveSecretGenerationFailed = -213414,

/* Returned when the point for the curve does not correspond to expected size. */
	KOpenPGPElliptic_CurveMalformedPoint = -213415,

/* Returned when computation over this elliptic curve isn't supported. */
	KOpenPGPElliptic_CurveUnsupported = -213416,

/* Returned when export of a MPI into a buffer failed. */
	KOpenPGPElliptic_CurveExportFailed = -213417,

/* Returned when EC verification context init failed. */
	KOpenPGPElliptic_CurveVerificationContextInitFailed = -213418,

/* Returned when the nonce supplied is < KECDSA_MinNonceLength bytes long. */
	KOpenPGPElliptic_CurveSignatureNonceTooShort = -213419,

/* Returned when the target buffer is too short. */
	KOpenPGPElliptic_CurveTargetBufferTooShort = -213420,

/* Returned when EC signing context init failed. */
	KOpenPGPElliptic_CurveSignContextInitFailed = -213421,

/* Returned when ECDH is being run with Legacy 25519 curve. This is not supported yet. */
	KOpenPGPElliptic_Legacy25519ECDHNotSupportedYet = -213422,

/* Returned when Montgomery curve-like computation could not be run. */
	KOpenPGPElliptic_MontgomeryComputationError = -213423,

/* Returned when ,,,*/
	KOpenPGPElliptic_LegacyCurvePlaceholderError = -213424,

/* Returned when loading of the putative ephemeral private key from a supplied structure failed. */
	KOpenPGPElliptic_EphemeralPrivateKeyLoadingFailed = -213425,

/* This char indicates native format of the provided EC point, typical for legacy 25519 curves. */
	KOpenPGPElliptic_NativeFormatIndicator = 0x40,

/* Uncompressed points are in the 0x04 || X || Y format. */
	KOpenPGPElliptic_UncompressedPointIndicator = 0x04,
};

#endif /* __OPENPGP_LAYER_CONSTANTS_H__ */
