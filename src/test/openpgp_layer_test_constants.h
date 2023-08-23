#ifndef OPENPGP_LAYER_TEST_CONSTANTS_H
#define OPENPGP_LAYER_TEST_CONSTANTS_H

/**
 * Possible error codes returned from the testing methods.
 */
enum OpenPGPTestErrors {
	KOpenPGPEllipticTest_OK = 0,
	KOpenPGPEllipticTest_MissingTestVectorDefinitions			= -321545,
	KOpenPGPEllipticTest_EphemeralPublicKeyLengthMismatch		= -321546,
	KOpenPGPEllipticTest_EphemeralPublicKeyContentMismatch	= -321547,
	KOpenPGPEllipticTest_EphemeralPublicKeyUndefined = -321548,
	KOpenPGPEllipticTest_SharedSecretLengthMismatch = -321549,
	KOpenPGPEllipticTest_SharedSecretContentMismatch = -321550,
	KOpenPGPEllipticTest_SharedSecretUndefined = -321551,
	KOpenPGPEllipticTest_SignatureLengthMismatch = -321552,
	KOpenPGPEllipticTest_SignatureContentMismatch = -321553
};

#endif
